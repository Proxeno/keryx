using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using Keryx.Stun;
using Xunit;

namespace Keryx.Ice.Tests;

/// <summary>
/// End-to-end tests for <see cref="IceAgent"/>: gathering, RFC 8445 connectivity checks between
/// two agents on the loopback interface, role-conflict resolution, and the RFC 7983
/// demultiplexing rule that hands every non-STUN datagram to the exposed transport.
/// </summary>
public sealed class IceAgentTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(8);
    private static readonly int ReceiveTimeoutMs = 5000;

    private static CancellationToken Timeout(int seconds = 30)
        => new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    private static IceAgentOptions LoopbackOptions(IceRole role, ulong? tieBreaker = null) => new()
    {
        Role = role,
        BindAddress = IPAddress.Loopback,
        TieBreaker = tieBreaker,
        CheckInterval = TimeSpan.FromMilliseconds(20),
        CheckRetransmissionTimeout = TimeSpan.FromMilliseconds(150),
        KeepaliveInterval = TimeSpan.FromMilliseconds(500),
    };

    private static BlockingCollection<byte[]> Capture(IceAgent agent)
    {
        var queue = new BlockingCollection<byte[]>();
        agent.Transport.OnReceived += datagram => queue.Add(datagram.ToArray());
        return queue;
    }

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

    [Fact]
    public async Task TwoLoopbackAgents_ConnectAndCarryDatagramsBothWays()
    {
        var cancellationToken = Timeout();
        using var offerer = new IceAgent(LoopbackOptions(IceRole.Controlling));
        using var answerer = new IceAgent(LoopbackOptions(IceRole.Controlled));

        var offererInbox = Capture(offerer);
        var answererInbox = Capture(answerer);

        var offererStates = new List<IceAgentState>();
        offerer.OnStateChanged += (_, state) =>
        {
            lock (offererStates)
            {
                offererStates.Add(state);
            }
        };

        // Trickle candidates through SDP attribute syntax, the way signalling would.
        Trickle(offerer, answerer);
        Trickle(answerer, offerer);

        offerer.SetRemoteCredentials(answerer.LocalUfrag, answerer.LocalPassword);
        answerer.SetRemoteCredentials(offerer.LocalUfrag, offerer.LocalPassword);

        await offerer.StartGatheringAsync(cancellationToken);
        await answerer.StartGatheringAsync(cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        offerer.State.Should().Be(IceAgentState.Connected);
        answerer.State.Should().Be(IceAgentState.Connected);

        // Regular nomination: the controlling agent nominates one pair and both agents converge on
        // it. Nomination follows connection by a check, so wait for it rather than assume it.
        (await WaitUntilAsync(() => offerer.SelectedPair is { Nominated: true }, ConnectTimeout))
            .Should().BeTrue();
        (await WaitUntilAsync(() => answerer.SelectedPair is not null, ConnectTimeout))
            .Should().BeTrue();
        offerer.SelectedPair!.State.Should().Be(IceCandidatePairState.Succeeded);
        offerer.SelectedPair.RemoteEndPoint.Should().Be(answerer.LocalEndPoint);
        answerer.SelectedPair!.RemoteEndPoint.Should().Be(offerer.LocalEndPoint);

        // A DTLS-shaped record (first byte 20-63) and an RTP-shaped packet (128-191) must both
        // reach the far side's transport untouched.
        var dtls = new byte[] { 22, 0xFE, 0xFD, 0x00, 0x00, 0x01, 0x02, 0x03 };
        var rtp = new byte[] { 128, 0x60, 0x00, 0x2A, 0xDE, 0xAD, 0xBE, 0xEF };

        offerer.Transport.Send(dtls);
        answerer.Transport.Send(rtp);

        answererInbox.TryTake(out var atAnswerer, ReceiveTimeoutMs).Should().BeTrue();
        atAnswerer.Should().Equal(dtls);

        offererInbox.TryTake(out var atOfferer, ReceiveTimeoutMs).Should().BeTrue();
        atOfferer.Should().Equal(rtp);

        offerer.Transport.MaxDatagramSize.Should().Be(1472);

        lock (offererStates)
        {
            offererStates.Should().ContainInOrder(
                IceAgentState.Gathering, IceAgentState.Checking, IceAgentState.Connected);
        }
    }

    [Fact]
    public async Task LosingThePeerMovesTheAgentThroughDisconnectedToFailed()
    {
        var cancellationToken = Timeout();
        var options = LoopbackOptions(IceRole.Controlling);
        options.KeepaliveInterval = TimeSpan.FromMilliseconds(100);
        options.DisconnectedTimeout = TimeSpan.FromMilliseconds(400);
        options.ConsentTimeout = TimeSpan.FromMilliseconds(900);

        using var survivor = new IceAgent(options);
        var peer = new IceAgent(LoopbackOptions(IceRole.Controlled));

        var seen = new List<IceAgentState>();
        var failed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        survivor.OnStateChanged += (_, state) =>
        {
            lock (seen)
            {
                seen.Add(state);
            }

            if (state == IceAgentState.Failed)
            {
                failed.TrySetResult();
            }
        };

        Trickle(survivor, peer);
        Trickle(peer, survivor);
        survivor.SetRemoteCredentials(peer.LocalUfrag, peer.LocalPassword);
        peer.SetRemoteCredentials(survivor.LocalUfrag, survivor.LocalPassword);

        await survivor.StartGatheringAsync(cancellationToken);
        await peer.StartGatheringAsync(cancellationToken);
        (await survivor.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        peer.Dispose();

        await failed.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);

        lock (seen)
        {
            seen.Should().ContainInOrder(
                IceAgentState.Connected, IceAgentState.Disconnected, IceAgentState.Failed);
        }
    }

    [Fact]
    public async Task RegularNomination_FreezesTheSelectedPair_WhenAHigherPriorityPairSucceedsLater()
    {
        var cancellationToken = Timeout();
        using var offerer = new IceAgent(LoopbackOptions(IceRole.Controlling));
        using var answerer = new IceAgent(LoopbackOptions(IceRole.Controlled));

        // Only the answerer trickles nothing back automatically: the offerer's remote candidates are
        // injected by hand so this test controls exactly which pairs exist and their priorities.
        Trickle(offerer, answerer);
        offerer.SetRemoteCredentials(answerer.LocalUfrag, answerer.LocalPassword);
        answerer.SetRemoteCredentials(offerer.LocalUfrag, offerer.LocalPassword);

        await offerer.StartGatheringAsync(cancellationToken);
        await answerer.StartGatheringAsync(cancellationToken);

        var selectedChanges = 0;
        offerer.OnSelectedPairChanged += (_, _) => Interlocked.Increment(ref selectedChanges);

        var answererEndPoint = answerer.LocalEndPoint!;

        // A low-priority host pair to the answerer. It is the only pair, so the controlling agent
        // nominates it and freezes.
        offerer.AddRemoteCandidate(new IceCandidate(
            "low", 1, "udp", priority: 500u, answererEndPoint.Address, answererEndPoint.Port, IceCandidateType.Host));

        (await WaitUntilAsync(() => offerer.SelectedPair is { Nominated: true }, ConnectTimeout))
            .Should().BeTrue();
        var nominated = offerer.SelectedPair!;
        nominated.Remote.Type.Should().Be(IceCandidateType.Host);
        var changesAfterNomination = Volatile.Read(ref selectedChanges);

        // Now a far higher-priority pair to the same answerer appears and succeeds. Under aggressive
        // nomination this would re-point live media; regular nomination must keep the frozen pair.
        offerer.AddRemoteCandidate(new IceCandidate(
            "high", 1, "udp", priority: 2_000_000_000u, answererEndPoint.Address, answererEndPoint.Port,
            IceCandidateType.ServerReflexive, IPAddress.Loopback, offerer.LocalEndPoint!.Port));

        var higher = await WaitUntilAsync(
            () => offerer.CheckList.Any(p =>
                p.Remote.Type == IceCandidateType.ServerReflexive && p.State == IceCandidatePairState.Succeeded),
            ConnectTimeout);
        higher.Should().BeTrue("the higher-priority pair must actually succeed for the freeze to mean anything");

        // Give any (incorrect) re-selection a chance to happen before asserting it did not.
        await Task.Delay(300, cancellationToken);

        offerer.SelectedPair.Should().BeSameAs(nominated);
        offerer.SelectedPair!.Nominated.Should().BeTrue();
        var higherPair = offerer.CheckList.Single(p => p.Remote.Type == IceCandidateType.ServerReflexive);
        higherPair.Priority.Should().BeGreaterThan(nominated.Priority);
        higherPair.Nominated.Should().BeFalse();
        Volatile.Read(ref selectedChanges).Should().Be(changesAfterNomination, "the frozen selection must not change");
    }

    [Fact]
    public async Task RegularNomination_FailsOverToAnotherValidPair_WhenTheNominatedPairGoesDead()
    {
        var cancellationToken = Timeout();
        var options = LoopbackOptions(IceRole.Controlling);
        options.KeepaliveInterval = TimeSpan.FromMilliseconds(100);
        options.DisconnectedTimeout = TimeSpan.FromMilliseconds(400);
        options.ConsentTimeout = TimeSpan.FromSeconds(5);

        // The offerer authenticates every check with the one remote password it was told, so both
        // peers must present the same credentials for the offerer's checks to reach either of them.
        var sharedOptionsFor = (Func<IceAgentOptions>)(() =>
        {
            var peerOptions = LoopbackOptions(IceRole.Controlled);
            peerOptions.LocalUfrag = "peershare";
            peerOptions.LocalPassword = "sharedpasswordsharedpassword";
            return peerOptions;
        });

        using var offerer = new IceAgent(options);
        var primary = new IceAgent(sharedOptionsFor());
        using var backup = new IceAgent(sharedOptionsFor());

        // Both peers can answer the offerer's checks, but only the offerer's manually injected
        // remote candidates decide which endpoints it pairs with and in what priority order.
        Trickle(offerer, primary);
        Trickle(offerer, backup);
        offerer.SetRemoteCredentials(primary.LocalUfrag, primary.LocalPassword);
        primary.SetRemoteCredentials(offerer.LocalUfrag, offerer.LocalPassword);
        backup.SetRemoteCredentials(offerer.LocalUfrag, offerer.LocalPassword);

        await offerer.StartGatheringAsync(cancellationToken);
        await primary.StartGatheringAsync(cancellationToken);
        await backup.StartGatheringAsync(cancellationToken);

        var primaryEndPoint = primary.LocalEndPoint!;
        var backupEndPoint = backup.LocalEndPoint!;

        // Add only the high-priority pair first so it is the one that gets nominated.
        offerer.AddRemoteCandidate(new IceCandidate(
            "high", 1, "udp", priority: 2_000_000_000u, primaryEndPoint.Address, primaryEndPoint.Port,
            IceCandidateType.Host));

        (await WaitUntilAsync(
            () => offerer.SelectedPair is { Nominated: true } s && Equals(s.RemoteEndPoint, primaryEndPoint),
            ConnectTimeout)).Should().BeTrue();

        // Now add the lower-priority backup pair and let it succeed so it is available to fail over to.
        offerer.AddRemoteCandidate(new IceCandidate(
            "low", 1, "udp", priority: 500u, backupEndPoint.Address, backupEndPoint.Port, IceCandidateType.Host));

        (await WaitUntilAsync(
            () => offerer.CheckList.Any(p =>
                Equals(p.RemoteEndPoint, backupEndPoint) && p.State == IceCandidatePairState.Succeeded),
            ConnectTimeout)).Should().BeTrue();

        var everFailed = false;
        offerer.OnStateChanged += (_, state) =>
        {
            if (state is IceAgentState.Failed)
            {
                everFailed = true;
            }
        };

        // Kill the nominated peer. Consent on the selected pair lapses, and regular nomination must
        // fail over to the still-valid backup pair instead of tearing the session down.
        primary.Dispose();

        (await WaitUntilAsync(
            () => offerer.SelectedPair is { Nominated: true } s && Equals(s.RemoteEndPoint, backupEndPoint),
            TimeSpan.FromSeconds(8))).Should().BeTrue();

        offerer.State.Should().Be(IceAgentState.Connected);
        everFailed.Should().BeFalse();
    }

    [Fact]
    public async Task AggressiveNomination_ReSelectsAHigherPriorityPairThatSucceedsLater()
    {
        var cancellationToken = Timeout();
        var options = LoopbackOptions(IceRole.Controlling);
        options.NominationMode = IceNominationMode.Aggressive;

        using var offerer = new IceAgent(options);
        using var answerer = new IceAgent(LoopbackOptions(IceRole.Controlled));

        Trickle(offerer, answerer);
        offerer.SetRemoteCredentials(answerer.LocalUfrag, answerer.LocalPassword);
        answerer.SetRemoteCredentials(offerer.LocalUfrag, offerer.LocalPassword);

        await offerer.StartGatheringAsync(cancellationToken);
        await answerer.StartGatheringAsync(cancellationToken);

        var answererEndPoint = answerer.LocalEndPoint!;
        offerer.AddRemoteCandidate(new IceCandidate(
            "low", 1, "udp", priority: 500u, answererEndPoint.Address, answererEndPoint.Port, IceCandidateType.Host));

        (await WaitUntilAsync(() => offerer.SelectedPair is { Nominated: true }, ConnectTimeout))
            .Should().BeTrue();

        offerer.AddRemoteCandidate(new IceCandidate(
            "high", 1, "udp", priority: 2_000_000_000u, answererEndPoint.Address, answererEndPoint.Port,
            IceCandidateType.ServerReflexive, IPAddress.Loopback, offerer.LocalEndPoint!.Port));

        // Aggressive nomination deliberately re-selects: the higher-priority pair becomes selected
        // once it succeeds. This is the behaviour regular nomination exists to avoid.
        (await WaitUntilAsync(
            () => offerer.SelectedPair!.Remote.Type == IceCandidateType.ServerReflexive, ConnectTimeout))
            .Should().BeTrue();
        offerer.SelectedPair!.Nominated.Should().BeTrue();
    }

    [Fact]
    public async Task CheckListFormation_UnfreezesOnlyTheRepresentativePairPerFoundation()
    {
        var cancellationToken = Timeout();
        using var agent = new IceAgent(LoopbackOptions(IceRole.Controlling));

        var peerA = new IPEndPoint(IPAddress.Loopback, 41001);
        var peerB = new IPEndPoint(IPAddress.Loopback, 41002);
        var peerC = new IPEndPoint(IPAddress.Loopback, 41003);

        // Added before gathering has produced a local candidate, so none of these can form a pair
        // yet: all three form together in the single check-list rebuild that runs once the local
        // host candidate appears, which is exactly when the per-foundation, priority-ordered
        // tie-break (RFC 8445 section 6.1.2.6) has more than one candidate to choose from. peerA and
        // peerB share a foundation; peerC has a distinct one. Remote credentials are never set, so
        // TickLocked always bails out before it can start a check, keeping the check list's states
        // below a pure snapshot of formation with no race against the background check loop.
        agent.AddRemoteCandidate(new IceCandidate(
            "grp", 1, "udp", 100u, peerA.Address, peerA.Port, IceCandidateType.Host));
        agent.AddRemoteCandidate(new IceCandidate(
            "grp", 1, "udp", 200u, peerB.Address, peerB.Port, IceCandidateType.Host));
        agent.AddRemoteCandidate(new IceCandidate(
            "solo", 1, "udp", 50u, peerC.Address, peerC.Port, IceCandidateType.Host));

        await agent.StartGatheringAsync(cancellationToken);

        var pairs = agent.CheckList;
        pairs.Should().HaveCount(3);

        var grouped = pairs.Where(p => p.Remote.Foundation == "grp").ToList();
        grouped.Should().HaveCount(2);
        grouped.Count(p => p.State == IceCandidatePairState.Frozen).Should().Be(1,
            "only one pair per foundation may start unfrozen");
        grouped.Single(p => p.State != IceCandidatePairState.Frozen).Remote.EndPoint.Should().Be(peerB,
            "the higher-priority pair in a tied foundation group becomes the representative");

        var solo = pairs.Single(p => p.Remote.Foundation == "solo");
        solo.State.Should().Be(IceCandidatePairState.Waiting,
            "a pair alone in its foundation is its own representative and starts checkable");
    }

    [Fact]
    public async Task SuccessfulCheck_UnfreezesAndEventuallyChecksItsFoundationSiblings()
    {
        var cancellationToken = Timeout();
        var options = LoopbackOptions(IceRole.Controlling);
        options.MaxCheckTransmissions = 2; // fail the unreachable sibling quickly once unfrozen

        using var offerer = new IceAgent(options);
        using var reachable = new IceAgent(LoopbackOptions(IceRole.Controlled));

        // Bound but never driven by an ICE agent, so a check sent to it can never get an answer.
        using var unreachableSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        unreachableSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var unreachableEndPoint = (IPEndPoint)unreachableSocket.LocalEndPoint!;

        Trickle(offerer, reachable);
        offerer.SetRemoteCredentials(reachable.LocalUfrag, reachable.LocalPassword);
        reachable.SetRemoteCredentials(offerer.LocalUfrag, offerer.LocalPassword);

        await offerer.StartGatheringAsync(cancellationToken);
        await reachable.StartGatheringAsync(cancellationToken);

        var reachableEndPoint = reachable.LocalEndPoint!;

        // Both remote candidates share one foundation. The reachable one has the higher priority, so
        // it becomes the initial representative and starts Waiting; the unreachable one starts Frozen.
        offerer.AddRemoteCandidate(new IceCandidate(
            "grp", 1, "udp", priority: 2_000_000_000u, reachableEndPoint.Address, reachableEndPoint.Port,
            IceCandidateType.Host));
        offerer.AddRemoteCandidate(new IceCandidate(
            "grp", 1, "udp", priority: 500u, unreachableEndPoint.Address, unreachableEndPoint.Port,
            IceCandidateType.Host));

        offerer.CheckList.Single(p => Equals(p.RemoteEndPoint, unreachableEndPoint)).State
            .Should().Be(IceCandidatePairState.Frozen);

        (await WaitUntilAsync(
            () => offerer.CheckList.Any(p =>
                Equals(p.RemoteEndPoint, reachableEndPoint) && p.State == IceCandidatePairState.Succeeded),
            ConnectTimeout)).Should().BeTrue();

        // The success must release the Frozen sibling (RFC 8445 section 7.2.5.3.3) so it is actually
        // scheduled - not just unfrozen and forgotten. It cannot succeed (nothing answers it), so
        // seeing it reach Failed proves a check was really sent for it.
        (await WaitUntilAsync(
            () => offerer.CheckList.Single(p => Equals(p.RemoteEndPoint, unreachableEndPoint)).State
                == IceCandidatePairState.Failed,
            ConnectTimeout)).Should().BeTrue("the unfrozen sibling must eventually be checked, even though it can never succeed");
    }

    [Fact]
    public async Task SingleFoundationScenario_StartsUnfrozenAndConnectsAsBefore()
    {
        var cancellationToken = Timeout();
        using var offerer = new IceAgent(LoopbackOptions(IceRole.Controlling));
        using var answerer = new IceAgent(LoopbackOptions(IceRole.Controlled));

        Trickle(offerer, answerer);
        Trickle(answerer, offerer);
        offerer.SetRemoteCredentials(answerer.LocalUfrag, answerer.LocalPassword);
        answerer.SetRemoteCredentials(offerer.LocalUfrag, offerer.LocalPassword);

        await offerer.StartGatheringAsync(cancellationToken);
        await answerer.StartGatheringAsync(cancellationToken);

        // With one local candidate gathered on each side (no STUN/TURN configured), each agent's
        // check list ends up holding exactly one pair: the sole representative of its own
        // foundation. It must start checkable - never Frozen - exactly as before freezing existed.
        (await WaitUntilAsync(() => offerer.CheckList.Count == 1, ConnectTimeout)).Should().BeTrue();
        offerer.CheckList.Single().State.Should().NotBe(IceCandidatePairState.Frozen);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        offerer.State.Should().Be(IceAgentState.Connected);
        answerer.State.Should().Be(IceAgentState.Connected);
    }

    [Theory]
    [InlineData(1000ul, 2000ul)]
    [InlineData(2000ul, 1000ul)]
    public async Task TwoControllingAgents_ResolveTheRoleConflictAndStillConnect(ulong firstTieBreaker, ulong secondTieBreaker)
    {
        var cancellationToken = Timeout();
        using var first = new IceAgent(LoopbackOptions(IceRole.Controlling, firstTieBreaker));
        using var second = new IceAgent(LoopbackOptions(IceRole.Controlling, secondTieBreaker));

        Trickle(first, second);
        Trickle(second, first);

        first.SetRemoteCredentials(second.LocalUfrag, second.LocalPassword);
        second.SetRemoteCredentials(first.LocalUfrag, first.LocalPassword);

        await first.StartGatheringAsync(cancellationToken);
        await second.StartGatheringAsync(cancellationToken);

        (await first.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await second.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        // RFC 8445 section 7.3.1.1: exactly one agent keeps the controlling role, and the agent
        // with the larger tie-breaker is the one that keeps it.
        first.Role.Should().NotBe(second.Role);
        var controlling = first.Role == IceRole.Controlling ? first : second;
        var controlled = ReferenceEquals(controlling, first) ? second : first;
        controlling.TieBreaker.Should().BeGreaterThan(controlled.TieBreaker);
    }

    [Fact]
    public async Task NonStunDatagramsAreSurfacedBeforeAnyPairIsSelected()
    {
        var cancellationToken = Timeout();
        using var agent = new IceAgent(new IceAgentOptions { BindAddress = IPAddress.Loopback });
        var inbox = Capture(agent);

        await agent.StartGatheringAsync(cancellationToken);
        var target = agent.LocalEndPoint!;
        agent.State.Should().Be(IceAgentState.Gathering);

        using var raw = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        raw.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        // DTLS can arrive immediately after the peer's first successful check, so nothing may be
        // buffered waiting for nomination.
        var dtls = new byte[] { 22, 0xFE, 0xFD, 0x09, 0x09 };
        raw.SendTo(dtls, target);

        inbox.TryTake(out var received, ReceiveTimeoutMs).Should().BeTrue();
        received.Should().Equal(dtls);
        agent.State.Should().Be(IceAgentState.Gathering);
    }

    [Fact]
    public async Task StunDatagramsAreConsumedInternallyAndNeverReachTheTransport()
    {
        var cancellationToken = Timeout();
        using var agent = new IceAgent(new IceAgentOptions { BindAddress = IPAddress.Loopback });
        var inbox = Capture(agent);

        await agent.StartGatheringAsync(cancellationToken);
        var target = agent.LocalEndPoint!;

        using var raw = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        raw.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        // An unauthenticated STUN Binding request: the agent must swallow it.
        raw.SendTo(StunMessage.CreateBindingRequest().Encode(appendFingerprint: true), target);

        // A trailing RTP-shaped packet proves the STUN datagram was skipped rather than delayed.
        var rtp = new byte[] { 128, 0x60, 0x00, 0x07 };
        raw.SendTo(rtp, target);

        inbox.TryTake(out var received, ReceiveTimeoutMs).Should().BeTrue();
        received.Should().Equal(rtp);
        inbox.Should().BeEmpty();
    }

    [Fact]
    public async Task StartGathering_ReportsHostCandidatesThenCompletion()
    {
        var cancellationToken = Timeout();
        var states = new List<IceAgentState>();
        var candidates = new List<IceCandidate>();
        var gatheringComplete = 0;

        using var agent = new IceAgent(new IceAgentOptions { BindAddress = IPAddress.Loopback });
        agent.OnStateChanged += (_, state) => states.Add(state);
        agent.OnLocalCandidate += (_, candidate) => candidates.Add(candidate);
        agent.OnGatheringComplete += (_, _) => Interlocked.Increment(ref gatheringComplete);

        agent.State.Should().Be(IceAgentState.New);
        await agent.StartGatheringAsync(cancellationToken);

        states.Should().StartWith(new[] { IceAgentState.Gathering });
        gatheringComplete.Should().Be(1);
        candidates.Should().ContainSingle();

        var candidate = candidates[0];
        candidate.Type.Should().Be(IceCandidateType.Host);
        candidate.Component.Should().Be(1);
        candidate.Transport.Should().Be("udp");
        candidate.Address.Should().Be(IPAddress.Loopback);
        candidate.Port.Should().Be(agent.LocalEndPoint!.Port);
        candidate.Priority.Should().Be(IcePriority.Compute(IceCandidateType.Host));

        // The gathered candidate must survive an SDP round trip.
        IceCandidate.Parse(candidate.ToSdpLine()).Should().Be(candidate);
        agent.LocalCandidates.Should().Equal(new[] { candidate });
    }

    [Fact]
    public async Task StartGathering_HonoursTheConfiguredPortRange()
    {
        var cancellationToken = Timeout();
        using var agent = new IceAgent(new IceAgentOptions
        {
            BindAddress = IPAddress.Loopback,
            MinPort = 7900,
            MaxPort = 7999,
        });

        await agent.StartGatheringAsync(cancellationToken);

        agent.LocalEndPoint!.Port.Should().BeInRange(7900, 7999);
        agent.LocalCandidates.Should().ContainSingle().Which.Port.Should().Be(agent.LocalEndPoint.Port);
    }

    [Fact]
    public async Task StartGathering_CannotBeCalledTwice()
    {
        var cancellationToken = Timeout();
        using var agent = new IceAgent(new IceAgentOptions { BindAddress = IPAddress.Loopback });
        await agent.StartGatheringAsync(cancellationToken);

        var act = async () => await agent.StartGatheringAsync(cancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public void Transport_ThrowsUntilAPairHasSucceeded()
    {
        using var agent = new IceAgent(new IceAgentOptions { BindAddress = IPAddress.Loopback });

        var act = () => agent.Transport.Send(new byte[] { 1, 2, 3 });

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Credentials_AreGeneratedWhenNotSupplied()
    {
        using var supplied = new IceAgent(new IceAgentOptions
        {
            LocalUfrag = "abcd",
            LocalPassword = "0123456789012345678901",
            TieBreaker = 42,
        });
        using var generated = new IceAgent();

        supplied.LocalUfrag.Should().Be("abcd");
        supplied.LocalPassword.Should().Be("0123456789012345678901");
        supplied.TieBreaker.Should().Be(42ul);

        generated.LocalUfrag.Length.Should().BeGreaterThanOrEqualTo(4);
        generated.LocalPassword.Length.Should().BeGreaterThanOrEqualTo(22);
        generated.Role.Should().Be(IceRole.Controlling);
        generated.State.Should().Be(IceAgentState.New);
        generated.SelectedPair.Should().BeNull();
    }

    [Fact]
    public async Task StartGathering_AddsAServerReflexiveCandidateFromTheConfiguredStunServer()
    {
        var cancellationToken = Timeout();
        var reflexive = new IPEndPoint(IPAddress.Parse("203.0.113.77"), 51234);

        using var stunServer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        stunServer.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var stunEndPoint = (IPEndPoint)stunServer.LocalEndPoint!;

        var responder = Task.Run(async () =>
        {
            var buffer = new byte[1500];
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            var received = await stunServer.ReceiveFromAsync(buffer, SocketFlags.None, from, cancellationToken);
            var request = StunMessage.Decode(buffer.AsSpan(0, received.ReceivedBytes));
            var response = StunMessage.CreateSuccessResponse(request)
                .Add(new StunXorMappedAddressAttribute(reflexive));
            stunServer.SendTo(response.Encode(appendFingerprint: true), received.RemoteEndPoint);
        }, cancellationToken);

        var options = new IceAgentOptions
        {
            BindAddress = IPAddress.Loopback,
            StunClientOptions = new StunClientOptions
            {
                InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(100),
                MaxTransmissions = 5,
                FinalWaitMultiplier = 4,
            },
        };
        options.StunServers.Add(stunEndPoint);

        using var agent = new IceAgent(options);
        await agent.StartGatheringAsync(cancellationToken);
        await responder;

        // The srflx query runs over the agent's own socket, not a throwaway one.
        var srflx = agent.LocalCandidates.Single(c => c.Type == IceCandidateType.ServerReflexive);
        srflx.EndPoint.Should().Be(reflexive);
        srflx.RelatedAddress.Should().Be(IPAddress.Loopback);
        srflx.RelatedPort.Should().Be(agent.LocalEndPoint!.Port);
        srflx.Priority.Should().Be(IcePriority.Compute(IceCandidateType.ServerReflexive));
        srflx.ToAttributeString().Should().Contain("typ srflx raddr 127.0.0.1 rport ");
        agent.LocalCandidates.Should().HaveCount(2);
    }

    [Fact]
    public async Task AddRemoteCandidate_AcceptsTrickledSdpAndRejectsGarbage()
    {
        var cancellationToken = Timeout();
        using var agent = new IceAgent(LoopbackOptions(IceRole.Controlling));
        await agent.StartGatheringAsync(cancellationToken);

        agent.AddRemoteCandidate("a=candidate:1 1 udp 2130706431 127.0.0.1 7999 typ host generation 0")
            .Should().BeTrue();
        agent.AddRemoteCandidate("nonsense").Should().BeFalse();

        agent.RemoteCandidates.Should().ContainSingle();
        agent.CheckList.Should().ContainSingle()
            .Which.Priority.Should().Be(
                IcePriority.ComputePair(agent.LocalCandidates[0].Priority, 2130706431u));
    }
}
