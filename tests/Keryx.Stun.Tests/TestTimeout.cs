namespace Keryx.Stun.Tests;

/// <summary>A shared cancellation token that trips if a test hangs, keeping the suite bounded.</summary>
internal static class TestTimeout
{
    /// <summary>Cancelled 30 seconds after the test assembly is loaded.</summary>
    public static CancellationToken Token { get; } = new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;
}
