using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using Xunit;

namespace Keryx.Ice.Tests;

/// <summary>
/// Intake of mDNS <c>&lt;uuid&gt;.local</c> remote host candidates: recognition (not silently
/// dropped as unparsable), routing to the resolver, and graceful degradation when resolution fails.
/// The resolver is stubbed so the routing logic is exercised without a live multicast responder.
/// </summary>
public sealed class IceAgentMdnsTests
{
    private const string MdnsCandidate =
        "candidate:1 1 udp 2130706431 3f4a1c9e-2b6d-4e11-9a7c-1d2e3f4a5b6c.local 50000 typ host generation 0";

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
    public async Task LocalCandidate_IsRecognisedRoutedToResolutionAndAddedOnSuccess()
    {
        var resolver = new StubMdnsResolver(IPAddress.Parse("192.168.1.42"));
        using var agent = new IceAgent(new IceAgentOptions { MdnsResolver = resolver });

        // Recognised, not dropped: the string overload returns true and hands off to the resolver.
        agent.AddRemoteCandidate(MdnsCandidate).Should().BeTrue();

        (await WaitUntilAsync(() => agent.RemoteCandidates.Count == 1, TimeSpan.FromSeconds(5)))
            .Should().BeTrue();

        resolver.RequestedHost.Should().Be("3f4a1c9e-2b6d-4e11-9a7c-1d2e3f4a5b6c.local");
        var resolved = agent.RemoteCandidates.Single();
        resolved.Type.Should().Be(IceCandidateType.Host);
        resolved.EndPoint.Should().Be(new IPEndPoint(IPAddress.Parse("192.168.1.42"), 50000));
    }

    [Fact]
    public async Task LocalCandidate_ThatDoesNotResolve_IsSkippedWithoutFaultingTheAgent()
    {
        var resolver = new StubMdnsResolver(result: null);
        using var agent = new IceAgent(new IceAgentOptions { MdnsResolver = resolver });

        // Still recognised at intake - the failure only shows up asynchronously.
        agent.AddRemoteCandidate(MdnsCandidate).Should().BeTrue();

        (await resolver.Called.Task.WaitAsync(TimeSpan.FromSeconds(5))).Should().BeTrue();
        // Give the (no-op) continuation a moment; nothing should be added and the agent stays New.
        await Task.Delay(100);
        agent.RemoteCandidates.Should().BeEmpty();
        agent.State.Should().Be(IceAgentState.New);
    }

    [Fact]
    public async Task LocalCandidate_WhenResolverThrows_IsSkippedGracefully()
    {
        var resolver = new ThrowingMdnsResolver();
        using var agent = new IceAgent(new IceAgentOptions { MdnsResolver = resolver });

        agent.AddRemoteCandidate(MdnsCandidate).Should().BeTrue();

        (await resolver.Called.Task.WaitAsync(TimeSpan.FromSeconds(5))).Should().BeTrue();
        await Task.Delay(100);
        agent.RemoteCandidates.Should().BeEmpty();
    }

    [Fact]
    public void LocalCandidate_IsTreatedAsUnparsableWhenResolutionIsDisabled()
    {
        var resolver = new StubMdnsResolver(IPAddress.Parse("192.168.1.42"));
        using var agent = new IceAgent(new IceAgentOptions
        {
            ResolveMdnsCandidates = false,
            MdnsResolver = resolver,
        });

        agent.AddRemoteCandidate(MdnsCandidate).Should().BeFalse();
        resolver.RequestedHost.Should().BeNull();
        agent.RemoteCandidates.Should().BeEmpty();
    }

    [Fact]
    public async Task MulticastResolver_ReturnsNullForAnUnansweredNameWithinItsTimeout()
    {
        // No responder for a random name: the real resolver must degrade to null, not throw, even
        // in a sandbox where the multicast send itself may be refused.
        var resolver = new MulticastMdnsResolver(TimeSpan.FromMilliseconds(300));

        var address = await resolver.ResolveAsync(
            $"{Guid.NewGuid()}.local", new CancellationTokenSource(TimeSpan.FromSeconds(5)).Token);

        address.Should().BeNull();
    }

    private sealed class StubMdnsResolver(IPAddress? result) : IMdnsResolver
    {
        public string? RequestedHost { get; private set; }

        public TaskCompletionSource<bool> Called { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<IPAddress?> ResolveAsync(string hostName, CancellationToken cancellationToken = default)
        {
            RequestedHost = hostName;
            Called.TrySetResult(true);
            return Task.FromResult(result);
        }
    }

    private sealed class ThrowingMdnsResolver : IMdnsResolver
    {
        public TaskCompletionSource<bool> Called { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<IPAddress?> ResolveAsync(string hostName, CancellationToken cancellationToken = default)
        {
            Called.TrySetResult(true);
            throw new SocketException((int)SocketError.NetworkUnreachable);
        }
    }
}
