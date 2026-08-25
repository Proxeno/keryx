using System.Net;
using FluentAssertions;
using Xunit;

namespace Keryx.Ice.Tests;

/// <summary>
/// Adversarial tests for the resource caps that keep a hostile signalling peer from turning remote
/// candidate intake into a denial of service: an mDNS <c>.local</c> flood must not spawn unbounded
/// concurrent resolutions (tasks and UDP sockets), and a raw candidate flood must not grow the
/// retained set and its derived check list without bound. Both caps must leave a legitimate,
/// single-digit session working.
/// </summary>
public sealed class IceAgentResourceCapTests
{
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

    private static string MdnsCandidate(Guid host, int port = 50000)
        => $"candidate:1 1 udp 2130706431 {host}.local {port} typ host generation 0";

    private static IceCandidate HostCandidate(int index)
        => new(
            foundation: $"f{index}",
            component: 1,
            IceCandidate.UdpTransport,
            priority: (uint)(2_130_706_431 - index),
            IPAddress.Parse($"10.{(index >> 8) & 0xFF}.{index & 0xFF}.7"),
            port: 40_000 + index,
            IceCandidateType.Host);

    // -------------------------------------------------------------- Finding 1: mDNS resolution cap

    [Fact]
    public async Task MdnsFlood_ResolvesNoMoreThanTheConcurrencyCapAtOnce()
    {
        // Every resolution blocks on this gate, so a slot is held for as long as the flood runs. With
        // the cap set to 4, only 4 of a 60-name flood may be resolving at any instant; the rest must
        // be dropped at intake rather than each spawning a task and its UDP sockets.
        using var gate = new GatedMdnsResolver();
        using var agent = new IceAgent(new IceAgentOptions
        {
            MdnsResolver = gate,
            MaxConcurrentMdnsResolutions = 4,
        });

        for (var i = 0; i < 60; i++)
        {
            agent.AddRemoteCandidate(MdnsCandidate(Guid.NewGuid())).Should().BeTrue();
        }

        // Let the admitted resolutions reach the gate, then give any wrongly-admitted extras time to
        // pile on before we assert the ceiling held.
        (await WaitUntilAsync(() => gate.Current == 4, TimeSpan.FromSeconds(5))).Should().BeTrue();
        await Task.Delay(300);

        gate.MaxObserved.Should().BeLessThanOrEqualTo(4,
            "at most MaxConcurrentMdnsResolutions resolutions - and their sockets - may run at once");

        // Releasing the gate lets the admitted resolutions finish (they return null); the flood must
        // not have faulted the agent, and nothing unresolved is added.
        gate.Release();
        await Task.Delay(100);
        agent.State.Should().Be(IceAgentState.New);
        agent.RemoteCandidates.Should().BeEmpty();
    }

    [Fact]
    public async Task MdnsFlood_OfOneRepeatedName_CollapsesToASingleResolution()
    {
        using var gate = new GatedMdnsResolver();
        using var agent = new IceAgent(new IceAgentOptions
        {
            MdnsResolver = gate,
            MaxConcurrentMdnsResolutions = 4,
        });

        var host = Guid.NewGuid();
        for (var i = 0; i < 40; i++)
        {
            agent.AddRemoteCandidate(MdnsCandidate(host)).Should().BeTrue();
        }

        (await WaitUntilAsync(() => gate.Current >= 1, TimeSpan.FromSeconds(5))).Should().BeTrue();
        await Task.Delay(300);

        gate.MaxObserved.Should().Be(1, "an identical in-flight name must be coalesced, not re-queried");

        gate.Release();
    }

    [Fact]
    public async Task LegitimateHandfulOfMdnsNames_AllResolveWithTheCapInPlace()
    {
        // A real same-LAN session obfuscates a single-digit number of host candidates. With the cap
        // set low, every one of a small, distinct set must still resolve and be added.
        var resolver = new MapMdnsResolver();
        var hosts = new Dictionary<Guid, IPAddress>();
        for (var i = 0; i < 5; i++)
        {
            var host = Guid.NewGuid();
            var address = IPAddress.Parse($"192.168.1.{10 + i}");
            hosts[host] = address;
            resolver.Map[$"{host}.local"] = address;
        }

        using var agent = new IceAgent(new IceAgentOptions
        {
            MdnsResolver = resolver,
            MaxConcurrentMdnsResolutions = 2,
        });

        var port = 50_000;
        foreach (var host in hosts.Keys)
        {
            agent.AddRemoteCandidate(MdnsCandidate(host, port++)).Should().BeTrue();
        }

        (await WaitUntilAsync(() => agent.RemoteCandidates.Count == hosts.Count, TimeSpan.FromSeconds(5)))
            .Should().BeTrue();

        agent.RemoteCandidates.Select(c => c.Address)
            .Should().BeEquivalentTo(hosts.Values);
    }

    // -------------------------------------------------------------- Finding 2: remote-candidate cap

    [Fact]
    public void RemoteCandidateFlood_IsCappedAndTheAgentKeepsFunctioning()
    {
        using var agent = new IceAgent(new IceAgentOptions { MaxRemoteCandidates = 10 });

        for (var i = 0; i < 500; i++)
        {
            // No throw, ever - beyond the cap the extra candidates are simply dropped.
            agent.AddRemoteCandidate(HostCandidate(i));
        }

        agent.RemoteCandidates.Should().HaveCount(10);

        // The agent is still usable: a further add does not fault it, it just stays at the cap.
        var addAgain = () => agent.AddRemoteCandidate(HostCandidate(10_000));
        addAgain.Should().NotThrow();
        agent.RemoteCandidates.Should().HaveCount(10);
        agent.State.Should().Be(IceAgentState.New);
    }

    [Fact]
    public async Task RemoteCandidateCap_DoesNotBreakALegitimateSmallSessionConnecting()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

        IceAgentOptions Options(IceRole role) => new()
        {
            Role = role,
            BindAddress = IPAddress.Loopback,
            MaxRemoteCandidates = 8,
            CheckInterval = TimeSpan.FromMilliseconds(20),
            CheckRetransmissionTimeout = TimeSpan.FromMilliseconds(150),
            KeepaliveInterval = TimeSpan.FromMilliseconds(500),
        };

        using var offerer = new IceAgent(Options(IceRole.Controlling));
        using var answerer = new IceAgent(Options(IceRole.Controlled));

        offerer.OnLocalCandidate += (_, c) => answerer.AddRemoteCandidate(c.ToSdpLine());
        answerer.OnLocalCandidate += (_, c) => offerer.AddRemoteCandidate(c.ToSdpLine());

        offerer.SetRemoteCredentials(answerer.LocalUfrag, answerer.LocalPassword);
        answerer.SetRemoteCredentials(offerer.LocalUfrag, offerer.LocalPassword);

        await offerer.StartGatheringAsync(cancellationToken);
        await answerer.StartGatheringAsync(cancellationToken);

        (await offerer.WaitForConnectedAsync(TimeSpan.FromSeconds(8), cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(TimeSpan.FromSeconds(8), cancellationToken)).Should().BeTrue();
    }

    /// <summary>
    /// A resolver that stands in for the socket-spawning production one: every call registers itself
    /// as an in-flight resolution and blocks until released, so the test can observe how many run at
    /// once. Concurrency here is a one-for-one proxy for the tasks and UDP sockets a real resolution
    /// would hold.
    /// </summary>
    private sealed class GatedMdnsResolver : IMdnsResolver, IDisposable
    {
        private readonly object _sync = new();
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _current;

        public int Current
        {
            get { lock (_sync) { return _current; } }
        }

        public int MaxObserved { get; private set; }

        public void Release() => _release.TrySetResult();

        public async Task<IPAddress?> ResolveAsync(string hostName, CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                _current++;
                MaxObserved = Math.Max(MaxObserved, _current);
            }

            try
            {
                await _release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // The agent's token fired; fall through and report unresolvable.
            }
            finally
            {
                lock (_sync)
                {
                    _current--;
                }
            }

            return null;
        }

        public void Dispose() => Release();
    }

    /// <summary>A non-blocking resolver that answers from a fixed name-to-address map.</summary>
    private sealed class MapMdnsResolver : IMdnsResolver
    {
        public Dictionary<string, IPAddress> Map { get; } = new(StringComparer.OrdinalIgnoreCase);

        public Task<IPAddress?> ResolveAsync(string hostName, CancellationToken cancellationToken = default)
            => Task.FromResult(Map.TryGetValue(hostName, out var address) ? address : null);
    }
}
