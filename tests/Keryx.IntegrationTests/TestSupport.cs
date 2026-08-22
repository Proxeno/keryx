using System.Net;
using Keryx;
using Keryx.Core;
using Xunit;

// Every test in this assembly binds real UDP sockets in 7900-7999; running classes in parallel would
// let two sessions race for the same ports and for the loopback interface.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Keryx.IntegrationTests;

/// <summary>Shared helpers for the loopback integration tests.</summary>
internal static class TestSupport
{
    /// <summary>Lowest UDP port the tests are allowed to bind.</summary>
    internal const int MinPort = 7900;

    /// <summary>Highest UDP port the tests are allowed to bind.</summary>
    internal const int MaxPort = 7999;

    /// <summary>A config pinned to the loopback interface and the test port range.</summary>
    /// <param name="logger">Optional diagnostics sink.</param>
    internal static PeerConnectionConfig NewConfig(IKeryxLogger? logger = null) => new()
    {
        BindAddress = IPAddress.Loopback,
        MinPort = MinPort,
        MaxPort = MaxPort,
        Logger = logger ?? NullLogger.Instance,
        RtcpInterval = TimeSpan.FromMilliseconds(500),
        IceConnectTimeout = TimeSpan.FromSeconds(15),
    };

    /// <summary>Polls <paramref name="condition"/> until it holds or the timeout elapses.</summary>
    /// <param name="condition">The predicate to poll.</param>
    /// <param name="timeoutMilliseconds">How long to keep polling.</param>
    /// <returns>The final value of the predicate.</returns>
    internal static async Task<bool> WaitForAsync(Func<bool> condition, int timeoutMilliseconds = 15_000)
    {
        var deadline = Environment.TickCount64 + timeoutMilliseconds;
        while (Environment.TickCount64 < deadline)
        {
            if (condition())
            {
                return true;
            }

            await Task.Delay(20).ConfigureAwait(false);
        }

        return condition();
    }
}

/// <summary>One message a data channel delivered, captured for assertions.</summary>
/// <param name="Label">The channel label.</param>
/// <param name="Binary">True when the message arrived as binary rather than UTF-8 text.</param>
/// <param name="Payload">A copy of the message body.</param>
internal readonly record struct ChannelMessage(string Label, bool Binary, byte[] Payload);
