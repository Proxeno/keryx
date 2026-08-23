namespace Keryx.Sctp.Tests;

/// <summary>
/// A manually advanced clock so timed partial-reliability deadlines can be tested exactly, without
/// depending on real wall-clock sleeps. Does not override <see cref="TimeProvider.CreateTimer"/>, so
/// the association's periodic <c>Tick</c> still fires on real time (per
/// <see cref="SctpAssociationConfig.TickInterval"/>); only the deadline math driven by
/// <see cref="GetTimestamp"/>/<see cref="GetUtcNow"/> is under the test's control.
/// </summary>
internal sealed class TestTimeProvider : TimeProvider
{
    private long _timestamp;

    /// <inheritdoc />
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    /// <inheritdoc />
    public override long GetTimestamp() => _timestamp;

    /// <inheritdoc />
    public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddTicks(_timestamp);

    /// <summary>Moves the clock forward.</summary>
    /// <param name="delta">How far to advance.</param>
    internal void Advance(TimeSpan delta) => _timestamp += delta.Ticks;
}
