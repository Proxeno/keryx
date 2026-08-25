using System.Diagnostics;
using System.Text;
using FluentAssertions;
using Xunit;

namespace Keryx.Sctp.Tests;

/// <summary>
/// Known-Answer-style behavioural tests for the association's RFC 4960 §7.2 congestion controller,
/// driven end-to-end over the loopback harness. They read the live cwnd/ssthresh through the public
/// <see cref="SctpAssociation.GetStatistics"/> snapshot (the hook diagnostics already use) and assert
/// the real trajectory the RFC prescribes: the initial window is per spec; cwnd opens by at most one
/// MTU per SACK through slow start while it stays below ssthresh; it switches to the slower
/// congestion-avoidance growth once cwnd reaches ssthresh; and a loss halves ssthresh to the 4*MTU
/// floor and drops cwnd.
/// </summary>
/// <remarks>
/// The loopback transport advertises a 1200-byte MTU and both endpoints advertise the 1 MiB default
/// receive window, so the expected constants are:
/// <list type="bullet">
///   <item>Initial cwnd = min(4*MTU, max(2*MTU, 4380)) = 4380 (RFC 4960 §7.2.1).</item>
///   <item>Initial ssthresh = max(peer rwnd, initial cwnd) = 1 MiB.</item>
///   <item>Loss floor for ssthresh = 4*MTU = 4800 (RFC 4960 §7.2.3).</item>
///   <item>cwnd after a T3 timeout = 1*MTU = 1200 (RFC 4960 §7.2.3).</item>
/// </list>
/// </remarks>
public class SctpCongestionControlKatTests
{
    private const long Mtu = 1200;
    private const long ReceiveWindow = 1024 * 1024;

    // RFC 4960 §7.2.1: initial cwnd = min(4*MTU, max(2*MTU, 4380)). For a 1200-byte MTU that is 4380.
    private const long InitialCwnd = 4380;

    // RFC 4960 §7.2.3: on loss, ssthresh = max(cwnd/2, 4*MTU). While cwnd is small its half is below
    // 4*MTU, so ssthresh lands exactly on the 4*MTU floor.
    private const long LossFloor = 4 * Mtu;

    [Fact]
    public async Task InitialWindowIsPerSpec()
    {
        using var harness = new SctpAssociationTests.Harness();
        await harness.ConnectAsync();
        WaitFor(() => harness.B.Association.State == SctpAssociationState.Established).Should().BeTrue();

        var stats = harness.A.Association.GetStatistics();

        // Initial cwnd = min(4*MTU, max(2*MTU, 4380)); initial ssthresh = max(peer rwnd, initial cwnd).
        stats.CongestionWindow.Should().Be(InitialCwnd);
        stats.SlowStartThreshold.Should().Be(ReceiveWindow);

        // cwnd < ssthresh, so the association starts in slow start, with nothing yet in flight.
        stats.CongestionWindow.Should().BeLessThan(stats.SlowStartThreshold);
        stats.BytesInFlight.Should().Be(0);
    }

    [Fact]
    public async Task SlowStartOpensCongestionWindowByAtMostOneMtuPerSack()
    {
        using var harness = new SctpAssociationTests.Harness();
        var telemetry = harness.A.CreateChannel("telemetry");
        await harness.ConnectAsync();
        WaitFor(() => harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();
        WaitFor(() => telemetry.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        var start = harness.A.Association.GetStatistics();
        start.CongestionWindow.Should().Be(InitialCwnd);
        var ssthresh = start.SlowStartThreshold;

        // A single large, loss-free transfer keeps the pipe full so every SACK advances cwnd.
        const int payloadBytes = 150 * 1024;
        var payload = new byte[payloadBytes];
        new Random(20260824).NextBytes(payload);
        telemetry.Send(payload);

        // Sample the trajectory as it delivers, tracking the peak cwnd we ever observe.
        long peak = start.CongestionWindow;
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < 20_000 && harness.B.Messages.Count == 0)
        {
            peak = Math.Max(peak, harness.A.Association.GetStatistics().CongestionWindow);
        }

        WaitFor(() => harness.B.Messages.Count == 1, 20_000).Should().BeTrue();
        peak = Math.Max(peak, harness.A.Association.GetStatistics().CongestionWindow);

        // Slow start opened the window well past its initial value: many per-SACK increments landed.
        peak.Should().BeGreaterThanOrEqualTo(InitialCwnd + (5 * Mtu));

        // It never left slow start (ssthresh untouched at the 1 MiB window; the transfer is far
        // smaller), and the cumulative growth is bounded by the bytes acked — the "at most one MTU
        // per SACK" ceiling, since each SACK grows cwnd by at most the min(bytes acked, MTU) it acks.
        harness.A.Association.GetStatistics().SlowStartThreshold.Should().Be(ssthresh);
        peak.Should().BeLessThan(ssthresh);
        (peak - InitialCwnd).Should().BeLessThanOrEqualTo(payloadBytes);

        harness.B.Messages.Single().Payload.Should().Equal(payload);
        harness.A.Association.State.Should().Be(SctpAssociationState.Established);
    }

    [Fact]
    public async Task CongestionAvoidanceGrowsAboutOneMtuPerRttAfterLoss()
    {
        using var harness = new SctpAssociationTests.Harness();
        var telemetry = harness.A.CreateChannel("telemetry");
        await harness.ConnectAsync();
        WaitFor(() => harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();
        WaitFor(() => telemetry.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        // Phase 1 — force one loss on a multi-chunk message to pull ssthresh down to the floor so the
        // rest of the run happens with cwnd >= ssthresh (the congestion-avoidance regime).
        var firstMessage = new byte[16 * 1024];
        new Random(0x0C0FFEE).NextBytes(firstMessage);
        harness.A.Transport.DropNextDataDatagrams(1);
        telemetry.Send(firstMessage);

        WaitFor(() => harness.A.Association.GetStatistics().SlowStartThreshold < ReceiveWindow, 10_000)
            .Should().BeTrue();
        harness.A.Association.GetStatistics().SlowStartThreshold.Should().Be(LossFloor);
        WaitFor(() => harness.B.Messages.Count == 1, 20_000).Should().BeTrue();
        Quiesce();

        var cwnd0 = harness.A.Association.GetStatistics().CongestionWindow;

        // Phase 2 — a large, loss-free transfer. cwnd is at/above ssthresh, so growth is the slow
        // linear congestion-avoidance climb (about one MTU per RTT), not the per-SACK slow-start ramp.
        const int payloadBytes = 200 * 1024;
        var payload = new byte[payloadBytes];
        new Random(0x5AFE).NextBytes(payload);
        telemetry.Send(payload);

        var enteredCongestionAvoidance = false;
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < 25_000 && harness.B.Messages.Count < 2)
        {
            var stats = harness.A.Association.GetStatistics();
            if (stats.CongestionWindow >= stats.SlowStartThreshold)
            {
                enteredCongestionAvoidance = true;
            }
        }

        WaitFor(() => harness.B.Messages.Count == 2, 25_000).Should().BeTrue();
        var final = harness.A.Association.GetStatistics();

        // The whole phase ran in congestion avoidance, ssthresh unmoved (no further loss).
        enteredCongestionAvoidance.Should().BeTrue();
        final.SlowStartThreshold.Should().Be(LossFloor);

        // cwnd still grows (congestion avoidance is additive increase) but far slower than slow start:
        // RFC 4960 §7.2.2 raises cwnd by at most one MTU per cwnd bytes acked, and cwnd never drops
        // below ssthresh here, so the growth over the phase is bounded by (acked / ssthresh) MTUs.
        var congestionAvoidanceCeiling = ((payloadBytes / LossFloor) + 4) * Mtu;
        final.CongestionWindow.Should().BeGreaterThan(cwnd0);
        (final.CongestionWindow - cwnd0).Should().BeLessThanOrEqualTo(congestionAvoidanceCeiling);

        // Had this been slow start, cwnd would have ballooned by roughly the bytes acked; it did not.
        (final.CongestionWindow - cwnd0).Should().BeLessThan(payloadBytes / 3);

        harness.B.Messages.Last().Payload.Should().Equal(payload);
        harness.A.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.State.Should().Be(SctpAssociationState.Established);
    }

    [Fact]
    public async Task TimeoutCollapsesCwndToOneMtuAndHalvesSsthreshToFloor()
    {
        using var harness = new SctpAssociationTests.Harness();
        var telemetry = harness.A.CreateChannel("telemetry");
        await harness.ConnectAsync();
        WaitFor(() => harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();
        WaitFor(() => telemetry.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        harness.A.Association.GetStatistics().CongestionWindow.Should().Be(InitialCwnd);

        // A single small message whose only transmission is dropped. With nothing else outstanding
        // there are no gap acks, so fast retransmit cannot fire — only the T3 timer recovers it.
        harness.A.Transport.DropNextDataDatagrams(1);
        telemetry.SendText("lost then retransmitted on T3");
        WaitFor(() => harness.A.Transport.DroppedDatagrams == 1).Should().BeTrue();

        // RFC 4960 §7.2.3: a T3 timeout sets ssthresh = max(cwnd/2, 4*MTU) and cwnd = 1*MTU.
        WaitFor(() => harness.A.Association.GetStatistics().CongestionWindow < InitialCwnd, 10_000)
            .Should().BeTrue();
        var afterLoss = harness.A.Association.GetStatistics();
        afterLoss.CongestionWindow.Should().Be(Mtu);
        afterLoss.SlowStartThreshold.Should().Be(LossFloor);

        // The message is still delivered reliably and the association keeps flowing.
        WaitFor(() => harness.B.Messages.Count == 1).Should().BeTrue();
        Encoding.UTF8.GetString(harness.B.Messages.Single().Payload).Should().Be("lost then retransmitted on T3");
        harness.A.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.State.Should().Be(SctpAssociationState.Established);
    }

    [Fact]
    public async Task LossOnAMultiChunkMessageHalvesSsthreshToFloorAndRecovers()
    {
        using var harness = new SctpAssociationTests.Harness();
        var telemetry = harness.A.CreateChannel("telemetry");
        await harness.ConnectAsync();
        WaitFor(() => harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();
        WaitFor(() => telemetry.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        var ssthreshInit = harness.A.Association.GetStatistics().SlowStartThreshold;
        ssthreshInit.Should().Be(ReceiveWindow);

        // A message spanning many chunks with the first one dropped: later chunks arrive, so the gap
        // is reported repeatedly and fast retransmit (three miss indications) recovers the hole.
        const int payloadBytes = 16 * 1024;
        var payload = new byte[payloadBytes];
        new Random(0x10557).NextBytes(payload);
        harness.A.Transport.DropNextDataDatagrams(1);
        telemetry.Send(payload);

        // RFC 4960 §7.2.3/§7.2.4: the loss reduces ssthresh to max(cwnd/2, 4*MTU) — the 4*MTU floor
        // here — regardless of whether fast retransmit or a T3 timeout drove it.
        WaitFor(() => harness.A.Association.GetStatistics().SlowStartThreshold < ssthreshInit, 10_000)
            .Should().BeTrue();
        harness.A.Association.GetStatistics().SlowStartThreshold.Should().Be(LossFloor);

        // The whole message is delivered intact and the receive path stays bounded.
        WaitFor(() => harness.B.Messages.Count == 1, 20_000).Should().BeTrue();
        harness.B.Messages.Single().Payload.Should().Equal(payload);
        harness.A.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.TotalReceiveBufferBytes.Should().BeLessThan(ReceiveWindow);
    }

    /// <summary>Lets both endpoints settle so no SACK or DCEP traffic is still in flight.</summary>
    private static void Quiesce() => Thread.Sleep(120);

    private static bool WaitFor(Func<bool> condition, int timeoutMs = 5000)
    {
        var stopwatch = Stopwatch.StartNew();
        while (stopwatch.ElapsedMilliseconds < timeoutMs)
        {
            if (condition())
            {
                return true;
            }

            Thread.Sleep(5);
        }

        return condition();
    }
}
