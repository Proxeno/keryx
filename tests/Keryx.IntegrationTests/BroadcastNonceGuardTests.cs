using FluentAssertions;
using Keryx.Broadcast;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// The one-owner nonce-safety guard for the per-viewer key-bridge (<c>broadcast-scale.md</c> §4). A bridged
/// viewer's fan-out context and the connection's own <c>TryForwardRtp</c> path both encrypt under the ONE
/// DTLS-derived send master key; two SRTP index counters over one key+SSRC repeat the AES-CM keystream and
/// AES-GCM nonce (catastrophic). These tests prove the contract is <b>enforced</b>, not just documented: a
/// bridged SSRC can never also be forwarded, a forwarded SSRC can never be bridged, and an SSRC can be
/// bridged at most once — every collision throws.
/// </summary>
public sealed class BroadcastNonceGuardTests
{
    private static readonly SimulcastLayerId Hi = SimulcastLayerId.Parse("hi");
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout(int seconds = 90) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    [Fact]
    public async Task BridgingAnSsrc_ThenForwardingIt_Throws()
    {
        var cancellationToken = TestTimeout();
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = 1 });
        var (viewer, session) = await ConnectAsync(endpoint, cancellationToken);
        try
        {
            var ssrc = session.Connection.GetLocalSsrc(MediaKind.Video);
            var payloadType = session.Connection.GetNegotiatedPayloadType(MediaKind.Video)!.Value;

            var forwarder = new RtpForwarder(ssrc, outboundPayloadType: payloadType);
            forwarder.SelectLayer(Hi);
            using var subscriber = ViewerBroadcastBridge.CreateFanoutSubscriber(session, forwarder);

            // The bridged SSRC is now single-owner. Forwarding it on the connection's own send path would
            // drive a second index counter over the same key+SSRC — refused, loudly.
            var forward = () => session.Connection.TryForwardRtp(MediaKind.Video, new byte[64], 3000u, false, payloadType);
            forward.Should().Throw<InvalidOperationException>()
                .WithMessage("*already bridged*");
        }
        finally
        {
            await viewer.DisposeAsync();
        }
    }

    [Fact]
    public async Task ForwardingAnSsrc_ThenBridgingIt_Throws()
    {
        var cancellationToken = TestTimeout();
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = 1 });
        var (viewer, session) = await ConnectAsync(endpoint, cancellationToken);
        try
        {
            var ssrc = session.Connection.GetLocalSsrc(MediaKind.Video);
            var payloadType = session.Connection.GetNegotiatedPayloadType(MediaKind.Video)!.Value;

            // Forward once: the connection's own send path now owns this SSRC's index space.
            session.Connection.TryForwardRtp(MediaKind.Video, new byte[64], 3000u, false, payloadType)
                .Should().BeTrue();

            var forwarder = new RtpForwarder(ssrc, outboundPayloadType: payloadType);
            forwarder.SelectLayer(Hi);

            var bridge = () => ViewerBroadcastBridge.CreateFanoutSubscriber(session, forwarder);
            bridge.Should().Throw<InvalidOperationException>()
                .WithMessage("*already owned*");
        }
        finally
        {
            await viewer.DisposeAsync();
        }
    }

    [Fact]
    public async Task BridgingAnSsrcTwice_Throws()
    {
        var cancellationToken = TestTimeout();
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = 1 });
        var (viewer, session) = await ConnectAsync(endpoint, cancellationToken);
        try
        {
            var ssrc = session.Connection.GetLocalSsrc(MediaKind.Video);
            var payloadType = session.Connection.GetNegotiatedPayloadType(MediaKind.Video)!.Value;

            var forwarder1 = new RtpForwarder(ssrc, outboundPayloadType: payloadType);
            forwarder1.SelectLayer(Hi);
            using var first = ViewerBroadcastBridge.CreateFanoutSubscriber(session, forwarder1);

            var forwarder2 = new RtpForwarder(ssrc, outboundPayloadType: payloadType);
            forwarder2.SelectLayer(Hi);

            var secondBridge = () => ViewerBroadcastBridge.CreateFanoutSubscriber(session, forwarder2);
            secondBridge.Should().Throw<InvalidOperationException>()
                .WithMessage("*already owned*");
        }
        finally
        {
            await viewer.DisposeAsync();
        }
    }

    /// <summary>A viewer that is only forwarded (never bridged) keeps working — the guard fires solely on a
    /// genuine cross-path collision, not on the ordinary SFU forward path.</summary>
    [Fact]
    public async Task ForwardOnly_Viewer_IsUnaffectedByTheGuard()
    {
        var cancellationToken = TestTimeout();
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = 1 });
        var (viewer, session) = await ConnectAsync(endpoint, cancellationToken);
        try
        {
            var payloadType = session.Connection.GetNegotiatedPayloadType(MediaKind.Video)!.Value;
            for (var i = 0; i < 10; i++)
            {
                session.Connection.TryForwardRtp(MediaKind.Video, new byte[64], 3000u * (uint)(i + 1), false, payloadType)
                    .Should().BeTrue("repeated forwarding on the one connection send context is the normal path");
            }
        }
        finally
        {
            await viewer.DisposeAsync();
        }
    }

    private static async Task<(PeerConnection Viewer, ViewerSession Session)> ConnectAsync(
        BroadcastEndpoint endpoint,
        CancellationToken cancellationToken)
    {
        var viewer = new PeerConnection(TestSupport.NewConfig());
        var session = endpoint.AddViewer(TestSupport.NewConfig());
        var egress = session.Connection;

        viewer.OnLocalIceCandidate += (_, e) => egress.AddIceCandidate(e.Candidate, e.SdpMid);
        egress.OnLocalIceCandidate += (_, e) => viewer.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await viewer.CreateOfferAsync(cancellationToken);
        var recvonlyOffer = offer.Replace("a=sendonly", "a=recvonly", StringComparison.Ordinal);
        await egress.SetRemoteDescriptionAsync(recvonlyOffer, SdpType.Offer, cancellationToken);
        var answer = await egress.CreateAnswerAsync(cancellationToken);
        await viewer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await egress.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await viewer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await TestSupport.WaitForAsync(() => session.BoundEndPoints.Count > 0)).Should().BeTrue();

        return (viewer, session);
    }
}
