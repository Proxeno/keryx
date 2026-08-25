using System.Buffers.Binary;
using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Broadcast;
using Keryx.Rtp;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// ICE restart in endpoint-session mode (<c>broadcast-scale.md</c> §2, RFC 8445 §9): a viewer on the
/// shared-socket broadcast endpoint restarts ICE, the endpoint-session-mode agent — which owns no socket —
/// regenerates its ufrag/pwd and re-runs checks over the shared send seam, the endpoint re-registers the
/// new ufrag→session binding, and media keeps flowing. Before the fix <c>IceAgent.Restart</c> early-returned
/// for a socketless agent, so a restart was a silent no-op.
/// </summary>
public sealed class BroadcastIceRestartTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout(int seconds = 120) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    [Fact]
    public async Task ViewerIceRestart_RegeneratesEndpointSessionUfrag_AndMediaKeepsFlowing()
    {
        var cancellationToken = TestTimeout();

        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = 1 });

        var viewer = new PeerConnection(TestSupport.NewConfig());
        var session = endpoint.AddViewer(TestSupport.NewConfig());
        var egress = session.Connection;

        var received = new ConcurrentDictionary<int, byte>();
        viewer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video && payload.Length >= 4)
            {
                received.TryAdd(BinaryPrimitives.ReadInt32BigEndian(payload), 0);
            }
        };

        viewer.OnLocalIceCandidate += (_, e) => egress.AddIceCandidate(e.Candidate, e.SdpMid);
        egress.OnLocalIceCandidate += (_, e) => viewer.AddIceCandidate(e.Candidate, e.SdpMid);

        await NegotiateAsync(viewer, egress, iceRestart: false, cancellationToken);
        (await egress.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await viewer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var ufragBeforeRestart = egress.LocalIceUfrag;
        ufragBeforeRestart.Should().NotBeNull();
        session.LocalIceUfrag.Should().Be(ufragBeforeRestart);

        await ForwardAsync(egress, baseIndex: 0, count: 15, cancellationToken);
        (await TestSupport.WaitForAsync(() => received.Count >= 15)).Should().BeTrue("media flows before the restart");

        // ---- ICE restart, viewer-initiated ----
        await NegotiateAsync(viewer, egress, iceRestart: true, cancellationToken);

        // The endpoint-session-mode agent must have regenerated its credentials — the whole point of the
        // fix. A no-op restart would leave the ufrag unchanged.
        var ufragAfterRestart = egress.LocalIceUfrag;
        ufragAfterRestart.Should().NotBeNull().And.NotBe(ufragBeforeRestart,
            "an endpoint-session ICE restart must regenerate the local ufrag");

        // The endpoint adopts the new ufrag and moves its demux binding (needed for a first check arriving
        // from a fresh 5-tuple). The move is a real change the first time, and idempotent thereafter.
        endpoint.RebindViewerIceUfrag(session).Should().BeTrue();
        session.LocalIceUfrag.Should().Be(ufragAfterRestart);
        endpoint.RebindViewerIceUfrag(session).Should().BeFalse("the ufrag is already rebound");

        (await egress.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue(
            "the egress re-nominates a pair after the restart");
        (await viewer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        // Media keeps flowing after the restart. A handful of packets sent into the brief re-nomination
        // transient can be lost, so forward continuously and require a solid run to arrive — the point is
        // that the stream resumes over the shared socket, not that no transient packet is ever dropped.
        received.Clear();
        var flowing = false;
        for (var wave = 0; wave < 20 && !flowing; wave++)
        {
            await ForwardAsync(egress, baseIndex: 1000 + (wave * 100), count: 15, cancellationToken);
            flowing = received.Count >= 15;
        }

        flowing.Should().BeTrue("media keeps flowing over the shared socket after the ICE restart");

        await viewer.DisposeAsync();
    }

    private static async Task NegotiateAsync(
        PeerConnection viewer,
        PeerConnection egress,
        bool iceRestart,
        CancellationToken cancellationToken)
    {
        var offer = await viewer.CreateOfferAsync(iceRestart, cancellationToken);
        var recvonlyOffer = offer.Replace("a=sendonly", "a=recvonly", StringComparison.Ordinal);
        await egress.SetRemoteDescriptionAsync(recvonlyOffer, SdpType.Offer, cancellationToken);
        var answer = await egress.CreateAnswerAsync(cancellationToken);
        await viewer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);
    }

    private static async Task ForwardAsync(PeerConnection egress, int baseIndex, int count, CancellationToken cancellationToken)
    {
        var payloadType = egress.GetNegotiatedPayloadType(MediaKind.Video);
        payloadType.Should().NotBeNull();

        for (var i = 0; i < count; i++)
        {
            var payload = new byte[64];
            BinaryPrimitives.WriteInt32BigEndian(payload, baseIndex + i);
            egress.TryForwardRtp(MediaKind.Video, payload, 2_000_000u + ((uint)i * 3000u), marker: false, payloadType!.Value)
                .Should().BeTrue();
            await Task.Delay(3, cancellationToken);
        }
    }
}
