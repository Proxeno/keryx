namespace Keryx.Srtp;

/// <summary>
/// The Replay List of RFC 3711 Section 3.3.2, implemented as a sliding bitmap window over the
/// 48-bit SRTP packet index (or the 31-bit SRTCP index).
/// </summary>
/// <remarks>
/// The RFC requires a window of at least 64 entries; this uses 128. Checking and committing are
/// separate operations because RFC 3711 Section 3.3 requires the replay list to be consulted
/// before authentication and updated only after authentication succeeds.
/// </remarks>
internal struct SrtpReplayWindow
{
    /// <summary>Number of indices the window tracks behind the highest accepted index.</summary>
    public const int WindowSize = 128;

    private UInt128 _received;
    private ulong _highest;
    private bool _initialized;

    /// <summary>The highest index accepted so far; meaningless before the first commit.</summary>
    public readonly ulong Highest => _highest;

    /// <summary>
    /// Returns true when <paramref name="index"/> is ahead of the window, or inside it and not yet
    /// seen. Does not mutate state.
    /// </summary>
    public readonly bool IsAcceptable(ulong index)
    {
        if (!_initialized)
        {
            return true;
        }

        if (index > _highest)
        {
            return true;
        }

        var shift = _highest - index;
        if (shift >= WindowSize)
        {
            return false;
        }

        return (_received & (UInt128.One << (int)shift)) == UInt128.Zero;
    }

    /// <summary>Records <paramref name="index"/> as received, sliding the window forward if needed.</summary>
    public void Commit(ulong index)
    {
        if (!_initialized)
        {
            _initialized = true;
            _highest = index;
            _received = UInt128.One;
            return;
        }

        if (index > _highest)
        {
            var advance = index - _highest;
            _received = advance >= WindowSize ? UInt128.Zero : _received << (int)advance;
            _received |= UInt128.One;
            _highest = index;
            return;
        }

        var shift = _highest - index;
        if (shift < WindowSize)
        {
            _received |= UInt128.One << (int)shift;
        }
    }
}
