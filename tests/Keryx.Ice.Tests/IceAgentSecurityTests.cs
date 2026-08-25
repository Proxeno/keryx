using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using Keryx.Stun;
using Xunit;

namespace Keryx.Ice.Tests;

/// <summary>
/// Adversarial tests for <see cref="IceAgent"/> against an off-path attacker who can put UDP on the
/// agent's socket but holds none of the ICE short-term credentials: the pre-DTLS connectivity layer
/// is exposed to the network, so an unauthenticated datagram must never move security-relevant state.
/// </summary>
public sealed class IceAgentSecurityTests
{
    private static CancellationToken Timeout(int seconds = 30)
        => new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    private static IceAgentOptions LoopbackOptions(IceRole role) => new()
    {
        Role = role,
        BindAddress = IPAddress.Loopback,
        CheckInterval = TimeSpan.FromMilliseconds(20),
        CheckRetransmissionTimeout = TimeSpan.FromMilliseconds(150),
        KeepaliveInterval = TimeSpan.FromMilliseconds(100),
    };

    private static void Trickle(IceAgent from, IceAgent to)
        => from.OnLocalCandidate += (_, candidate) => to.AddRemoteCandidate(candidate.ToSdpLine());

    private static async Task<bool> WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        while (Environment.TickCount64 < deadline)
        {
            if (condition())
            {
                return true;
            }

            await Task.Delay(20);
        }

        return condition();
    }

    /// <summary>
    /// RFC 7675 section 5.1: consent to keep sending is refreshed only by a validated STUN Binding
    /// *response* to a request this agent sent. An inbound STUN Binding indication (the RFC 8445
    /// section 11 keepalive) carries no MESSAGE-INTEGRITY and its source is unverified, so it must
    /// not keep a dead selected pair's consent alive - otherwise an off-path attacker who can reach
    /// the socket keeps the agent transmitting to an address the real peer has abandoned, exactly
    /// the flooding that consent freshness exists to stop.
    /// </summary>
    [Fact]
    public async Task ForgedStunBindingIndications_DoNotKeepADeadSelectedPairAlive()
    {
        var cancellationToken = Timeout();
        var options = LoopbackOptions(IceRole.Controlling);
        options.DisconnectedTimeout = TimeSpan.FromMilliseconds(400);
        options.ConsentTimeout = TimeSpan.FromMilliseconds(900);

        using var survivor = new IceAgent(options);
        var peer = new IceAgent(LoopbackOptions(IceRole.Controlled));

        Trickle(survivor, peer);
        Trickle(peer, survivor);
        survivor.SetRemoteCredentials(peer.LocalUfrag, peer.LocalPassword);
        peer.SetRemoteCredentials(survivor.LocalUfrag, survivor.LocalPassword);

        await survivor.StartGatheringAsync(cancellationToken);
        await peer.StartGatheringAsync(cancellationToken);
        (await survivor.WaitForConnectedAsync(TimeSpan.FromSeconds(8), cancellationToken)).Should().BeTrue();
        (await WaitUntilAsync(() => survivor.SelectedPair is { Nominated: true }, TimeSpan.FromSeconds(8)))
            .Should().BeTrue();

        var target = new IPEndPoint(IPAddress.Loopback, survivor.LocalEndPoint!.Port);

        // The real peer goes away: nothing legitimate will answer the survivor's keepalive checks
        // any more, so genuine consent can no longer be refreshed.
        peer.Dispose();

        // The off-path attacker floods unauthenticated STUN Binding indications at the survivor's
        // socket. They pass the cheap STUN demultiplex but carry no credentials at all.
        var indication = StunMessage.CreateBindingIndication().Encode();
        using var attackerCts = new CancellationTokenSource();
        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        var flood = Task.Run(async () =>
        {
            while (!attackerCts.IsCancellationRequested)
            {
                try
                {
                    attacker.SendTo(indication, target);
                }
                catch (SocketException)
                {
                    // Socket transient; keep flooding.
                }

                await Task.Delay(30, attackerCts.Token).ConfigureAwait(false);
            }
        });

        try
        {
            var reachedFailed = await WaitUntilAsync(
                () => survivor.State == IceAgentState.Failed, TimeSpan.FromSeconds(10));
            reachedFailed.Should().BeTrue(
                "unauthenticated STUN Binding indications must not refresh consent on a dead pair");
        }
        finally
        {
            await attackerCts.CancelAsync();
            try
            {
                await flood;
            }
            catch (OperationCanceledException)
            {
                // Expected on cancellation.
            }
        }
    }

    /// <summary>
    /// An off-path attacker who knows the local ufrag (it is signalled in SDP) but not the password
    /// still cannot forge a connectivity check: a STUN Binding request whose MESSAGE-INTEGRITY does
    /// not key on the agent's short-term credential is dropped before it can create a peer-reflexive
    /// candidate, form a pair, or nominate anything (RFC 8445 section 7.3).
    /// </summary>
    [Fact]
    public async Task ForgedBindingRequest_WithoutValidMessageIntegrity_CreatesNoRemoteCandidate()
    {
        var cancellationToken = Timeout();
        using var agent = new IceAgent(LoopbackOptions(IceRole.Controlled));
        agent.SetRemoteCredentials("peerufrag", "peerpasswordpeerpassword");
        await agent.StartGatheringAsync(cancellationToken);

        var target = new IPEndPoint(IPAddress.Loopback, agent.LocalEndPoint!.Port);

        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        attacker.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        // A well-formed check with the right USERNAME prefix and a valid FINGERPRINT, but signed
        // with the wrong key - what an attacker who only learned the ufrag from SDP could produce.
        var request = new StunMessage(StunClass.Request, StunMethod.Binding)
            .Add(new StunUsernameAttribute($"{agent.LocalUfrag}:peerufrag"))
            .Add(new StunPriorityAttribute(1_000_000u))
            .Add(new StunIceControllingAttribute(0x1122334455667788UL))
            .Add(StunUseCandidateAttribute.Instance);
        var forged = request.Encode(StunCredentials.ShortTermKey("not-the-password"), appendFingerprint: true);

        for (var i = 0; i < 20; i++)
        {
            attacker.SendTo(forged, target);
            await Task.Delay(20, cancellationToken);
        }

        // The forged check must never have been acted on: no peer-reflexive candidate, no pair, and
        // the agent must not have been driven to Connected by an unauthenticated USE-CANDIDATE.
        agent.RemoteCandidates.Should().BeEmpty();
        agent.CheckList.Should().BeEmpty();
        agent.SelectedPair.Should().BeNull();
        agent.State.Should().NotBe(IceAgentState.Connected);
    }

    /// <summary>
    /// Establishes a connected, nominated pair of loopback agents and hands back a queue that
    /// captures every datagram <paramref name="receiver"/>'s transport surfaces, for the source
    /// validation tests below.
    /// </summary>
    private static async Task<(IceAgent Survivor, IceAgent Peer, List<byte[]> Received)> ConnectNominatedPairAsync(
        IceAgentOptions survivorOptions, CancellationToken cancellationToken)
    {
        var survivor = new IceAgent(survivorOptions);
        var peer = new IceAgent(LoopbackOptions(IceRole.Controlled));

        Trickle(survivor, peer);
        Trickle(peer, survivor);
        survivor.SetRemoteCredentials(peer.LocalUfrag, peer.LocalPassword);
        peer.SetRemoteCredentials(survivor.LocalUfrag, survivor.LocalPassword);

        var received = new List<byte[]>();
        survivor.Transport.OnReceived += datagram =>
        {
            lock (received)
            {
                received.Add(datagram.ToArray());
            }
        };

        await survivor.StartGatheringAsync(cancellationToken);
        await peer.StartGatheringAsync(cancellationToken);
        (await survivor.WaitForConnectedAsync(TimeSpan.FromSeconds(8), cancellationToken)).Should().BeTrue();
        (await WaitUntilAsync(() => survivor.SelectedPair is { Nominated: true }, TimeSpan.FromSeconds(8)))
            .Should().BeTrue();

        return (survivor, peer, received);
    }

    private static async Task<bool> ReceivedAnythingAsync(List<byte[]> received, TimeSpan timeout)
        => await WaitUntilAsync(
            () =>
            {
                lock (received)
                {
                    return received.Count > 0;
                }
            },
            timeout);

    /// <summary>
    /// The positive case behind <see cref="IceAgentOptions.StrictInboundSourceValidation"/>: once a
    /// pair is nominated, a non-STUN datagram genuinely from the peer - the address the selected
    /// pair's remote endpoint names - must still reach the transport. The defense-in-depth check must
    /// never interfere with the legitimate flow it is meant to protect.
    /// </summary>
    [Fact]
    public async Task StrictSourceValidation_PassesDatagramsFromTheSelectedPairsRemoteEndpoint()
    {
        var cancellationToken = Timeout();
        var (survivor, peer, received) = await ConnectNominatedPairAsync(
            LoopbackOptions(IceRole.Controlling), cancellationToken);
        using var _survivor = survivor;
        using var _peer = peer;

        byte[] dtls = [22, 0xFE, 0xFD, 0x01, 0x02, 0x03];
        peer.Transport.Send(dtls);

        (await ReceivedAnythingAsync(received, TimeSpan.FromSeconds(5))).Should().BeTrue();
        lock (received)
        {
            received.Should().ContainSingle();
            received[0].Should().Equal(dtls);
        }
    }

    /// <summary>
    /// The core defense-in-depth guarantee: once a pair is nominated, a non-STUN datagram whose
    /// source is not the selected pair's remote endpoint - exactly what an off-path attacker who can
    /// put UDP on the socket produces - never reaches the transport, even though it demultiplexes as
    /// DTLS/RTP/RTCP under RFC 7983 and would have been surfaced unconditionally before this change.
    /// </summary>
    [Fact]
    public async Task StrictSourceValidation_DropsDatagramsFromAnUnrelatedSource()
    {
        var cancellationToken = Timeout();
        var (survivor, peer, received) = await ConnectNominatedPairAsync(
            LoopbackOptions(IceRole.Controlling), cancellationToken);
        using var _survivor = survivor;
        using var _peer = peer;

        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        attacker.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var target = new IPEndPoint(IPAddress.Loopback, survivor.LocalEndPoint!.Port);

        byte[] forged = [22, 0xFE, 0xFD, 0xAA, 0xBB];
        attacker.SendTo(forged, target);

        // Not merely a race: send genuine media from the peer right after and confirm it is the only
        // thing that ever arrives, proving the forged datagram was dropped rather than delayed.
        byte[] legitimate = [22, 0xFE, 0xFD, 0x11, 0x22];
        peer.Transport.Send(legitimate);

        (await ReceivedAnythingAsync(received, TimeSpan.FromSeconds(5))).Should().BeTrue();
        lock (received)
        {
            received.Should().ContainSingle("the forged datagram from an unrelated source must be dropped");
            received[0].Should().Equal(legitimate);
        }
    }

    /// <summary>
    /// Turning <see cref="IceAgentOptions.StrictInboundSourceValidation"/> off restores the original
    /// unconditional RFC 7983 pass-through, so an integrator can disable the defense-in-depth check
    /// if it ever gets in the way of a legitimate path this test suite did not anticipate.
    /// </summary>
    [Fact]
    public async Task StrictSourceValidation_WhenDisabled_PassesDatagramsFromAnySource()
    {
        var cancellationToken = Timeout();
        var options = LoopbackOptions(IceRole.Controlling);
        options.StrictInboundSourceValidation = false;
        var (survivor, peer, received) = await ConnectNominatedPairAsync(options, cancellationToken);
        using var _survivor = survivor;
        using var _peer = peer;

        using var attacker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        attacker.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var target = new IPEndPoint(IPAddress.Loopback, survivor.LocalEndPoint!.Port);

        byte[] datagram = [22, 0xFE, 0xFD, 0x33, 0x44];
        attacker.SendTo(datagram, target);

        (await ReceivedAnythingAsync(received, TimeSpan.FromSeconds(5))).Should().BeTrue();
        lock (received)
        {
            received[0].Should().Equal(datagram);
        }
    }

    /// <summary>
    /// For a remote peer that reaches the survivor through the peer's own TURN server, the remote
    /// candidate's advertised transport address - and so the selected pair's remote endpoint - is the
    /// relay's address, not the peer's host address (RFC 8445 section 5.1: a relayed candidate's
    /// connection address is the relay). Validation must key off that address exactly like it does
    /// for a direct pair, not some other address the relay candidate happens to carry.
    /// </summary>
    [Fact]
    public async Task StrictSourceValidation_PassesRelayedPairTrafficFromTheRelayAddress()
    {
        var cancellationToken = Timeout();
        using var survivor = new IceAgent(LoopbackOptions(IceRole.Controlling));
        using var peer = new IceAgent(LoopbackOptions(IceRole.Controlled));

        // The peer's real, loopback-bound address is re-advertised to survivor as a "relay"
        // candidate - standing in for a peer whose only advertised path is through its own TURN
        // server. The address is unchanged; only the type claim changes, exactly like a real relayed
        // candidate whose connection address is the relay rather than the peer's host address.
        peer.OnLocalCandidate += (_, candidate) => survivor.AddRemoteCandidate(new IceCandidate(
            candidate.Foundation,
            candidate.Component,
            candidate.Transport,
            candidate.Priority,
            candidate.Address,
            candidate.Port,
            IceCandidateType.Relayed,
            candidate.RelatedAddress,
            candidate.RelatedPort));
        Trickle(survivor, peer);
        survivor.SetRemoteCredentials(peer.LocalUfrag, peer.LocalPassword);
        peer.SetRemoteCredentials(survivor.LocalUfrag, survivor.LocalPassword);

        var received = new List<byte[]>();
        survivor.Transport.OnReceived += datagram =>
        {
            lock (received)
            {
                received.Add(datagram.ToArray());
            }
        };

        await survivor.StartGatheringAsync(cancellationToken);
        await peer.StartGatheringAsync(cancellationToken);
        (await survivor.WaitForConnectedAsync(TimeSpan.FromSeconds(8), cancellationToken)).Should().BeTrue();
        (await WaitUntilAsync(() => survivor.SelectedPair is { Nominated: true }, TimeSpan.FromSeconds(8)))
            .Should().BeTrue();
        survivor.SelectedPair!.Remote.Type.Should().Be(IceCandidateType.Relayed);

        byte[] media = [128, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        peer.Transport.Send(media);

        (await ReceivedAnythingAsync(received, TimeSpan.FromSeconds(5))).Should().BeTrue();
        lock (received)
        {
            received[0].Should().Equal(media);
        }
    }
}
