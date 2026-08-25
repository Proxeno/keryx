using System.Diagnostics;
using System.Text;
using FluentAssertions;
using Xunit;

namespace Keryx.Sctp.Tests;

/// <summary>
/// Adversarial fault-injection tests that mangle a live association's DATA path with the
/// <see cref="DatagramCorruption"/> modes — bit-flips, truncation, duplication and checksum-valid
/// chunk-field mangling (bad lengths, bad TSNs, bad checksums). The robustness bar mirrors the rest
/// of the SCTP hardening suite: under transient corruption the association must never crash, hang or
/// grow its receive buffers without bound; corrupt packets are rejected cleanly; and once the
/// corruption stops the association recovers and keeps delivering user data reliably and in order.
/// </summary>
public class SctpFaultInjectionTests
{
    // Both endpoints advertise a 1 MiB receive window (SctpAssociationConfig default), so the entire
    // inbound receive path is hard-capped at that. Corruption must never push it past this.
    private const long ReceiveWindowCap = 1024 * 1024;

    /// <summary>
    /// Every mode that a correct receiver must reject outright (a stale CRC-32C, a truncated buffer,
    /// a valid-CRC chunk with an impossible length field, or a deliberately wrong checksum). The
    /// reliable channel must still deliver the message via retransmission.
    /// </summary>
    public static TheoryData<DatagramCorruption> RejectModes() => new()
    {
        DatagramCorruption.BitFlip,
        DatagramCorruption.Truncate,
        DatagramCorruption.BadChunkLength,
        DatagramCorruption.BadChecksum,
    };

    [Theory]
    [MemberData(nameof(RejectModes))]
    public async Task CorruptedDatagramIsRejectedAndReliableMessageStillArrives(DatagramCorruption mode)
    {
        using var harness = new SctpAssociationTests.Harness();
        var telemetry = harness.A.CreateChannel("telemetry");
        await harness.ConnectAsync();
        WaitFor(() => harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();
        WaitFor(() => telemetry.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        // Corrupt the one and only first transmission; recovery must come from retransmission.
        harness.A.Transport.CorruptNextDataDatagrams(1, mode);
        telemetry.SendText("must arrive intact");

        WaitFor(() => harness.B.Messages.Count == 1).Should().BeTrue();
        harness.A.Transport.CorruptedDatagrams.Should().Be(1);
        Encoding.UTF8.GetString(harness.B.Messages.Single().Payload).Should().Be("must arrive intact");

        // The association is unharmed and its receive path stayed bounded.
        harness.A.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.TotalReceiveBufferBytes.Should().BeLessThan(ReceiveWindowCap);
        WaitFor(() => telemetry.BufferedAmount == 0).Should().BeTrue();
    }

    [Fact]
    public async Task DuplicatedDatagramsAreDeliveredExactlyOnceInOrder()
    {
        using var harness = new SctpAssociationTests.Harness();
        var telemetry = harness.A.CreateChannel("telemetry");
        await harness.ConnectAsync();
        WaitFor(() => harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();
        WaitFor(() => telemetry.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        // Every one of the next six DATA datagrams is delivered twice on the wire.
        const int count = 6;
        harness.A.Transport.CorruptNextDataDatagrams(count, DatagramCorruption.Duplicate);
        for (var i = 0; i < count; i++)
        {
            telemetry.SendText($"dup{i}");
        }

        // SCTP dedupes by TSN, so exactly six messages are delivered up — no duplicates — in order.
        WaitFor(() => harness.B.Messages.Count == count).Should().BeTrue();
        Quiesce();
        harness.A.Transport.CorruptedDatagrams.Should().Be(count);
        harness.B.Messages.Count.Should().Be(count);
        harness.B.Messages.Select(m => Encoding.UTF8.GetString(m.Payload))
            .Should().Equal("dup0", "dup1", "dup2", "dup3", "dup4", "dup5");

        harness.A.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.TotalReceiveBufferBytes.Should().BeLessThan(ReceiveWindowCap);
    }

    [Fact]
    public async Task MangledTsnDoesNotCrashHangOrGrowBuffersUnbounded()
    {
        using var harness = new SctpAssociationTests.Harness();
        var telemetry = harness.A.CreateChannel("telemetry");
        await harness.ConnectAsync();
        WaitFor(() => harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();
        WaitFor(() => telemetry.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        // A valid-checksum DATA chunk whose TSN is shoved far out of the peer's window: it names data
        // the sender never transmitted. The receiver must neither wedge nor buffer it without bound.
        const int count = 8;
        harness.A.Transport.CorruptNextDataDatagrams(count, DatagramCorruption.BadTsn);
        for (var i = 0; i < count; i++)
        {
            telemetry.SendText($"tsn{i}");
        }

        // The real chunks are retransmitted (the mangled copies replaced their first transmission),
        // so every message still arrives, in order, once the corruption budget is exhausted.
        WaitFor(() => harness.B.Messages.Count == count, 20_000).Should().BeTrue();
        harness.A.Transport.CorruptedDatagrams.Should().Be(count);
        harness.B.Messages.Select(m => Encoding.UTF8.GetString(m.Payload))
            .Should().Equal(Enumerable.Range(0, count).Select(i => $"tsn{i}"));

        harness.A.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.TotalReceiveBufferBytes.Should().BeLessThan(ReceiveWindowCap);
        WaitFor(() => telemetry.BufferedAmount == 0).Should().BeTrue();
    }

    [Fact]
    public async Task SustainedMixedCorruptionThenRecovery()
    {
        using var harness = new SctpAssociationTests.Harness();
        var telemetry = harness.A.CreateChannel("telemetry");
        await harness.ConnectAsync();
        WaitFor(() => harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();
        WaitFor(() => telemetry.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        var modes = new[]
        {
            DatagramCorruption.BitFlip,
            DatagramCorruption.Truncate,
            DatagramCorruption.BadChunkLength,
            DatagramCorruption.BadTsn,
            DatagramCorruption.BadChecksum,
            DatagramCorruption.Duplicate,
        };

        var expected = new List<string>();
        var next = 0;

        // Hammer the data path: for each mode, corrupt a run of DATA datagrams while messages flow.
        foreach (var mode in modes)
        {
            harness.A.Transport.CorruptNextDataDatagrams(3, mode);
            for (var i = 0; i < 5; i++)
            {
                var text = $"m{next++}";
                expected.Add(text);
                telemetry.SendText(text);
            }

            // Let this mode's corruption and the ensuing recovery play out before the next mode.
            WaitFor(() => harness.B.Messages.Count == expected.Count, 20_000).Should().BeTrue();
            harness.B.Association.TotalReceiveBufferBytes.Should().BeLessThan(ReceiveWindowCap);
        }

        // After all corruption ceases a fresh message sails straight through, reliably and in order.
        telemetry.SendText("recovered");
        expected.Add("recovered");
        WaitFor(() => harness.B.Messages.Count == expected.Count).Should().BeTrue();

        harness.B.Messages.Select(m => Encoding.UTF8.GetString(m.Payload)).Should().Equal(expected);
        harness.A.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.TotalReceiveBufferBytes.Should().BeLessThan(ReceiveWindowCap);
        WaitFor(() => telemetry.BufferedAmount == 0).Should().BeTrue();
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
