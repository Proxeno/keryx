namespace Keryx.Dtls;

/// <summary>
/// The DTLS anti-replay sliding window (RFC 6347 §4.1.2.6), a 64-entry bitmap anchored at the
/// highest sequence number accepted so far.
/// </summary>
/// <remarks>
/// One window exists per read epoch; the window is discarded and recreated when the epoch advances,
/// because each epoch has its own sequence number space. Records below the window, or already
/// marked, are rejected. Callers must only call <see cref="Accept"/> after the record has been
/// authenticated, so that a forged sequence number cannot advance the window.
/// </remarks>
internal sealed class ReplayWindow
{
    public const int WindowSize = 64;

    private ulong _bitmap;
    private ulong _highest;
    private bool _seenAny;

    /// <summary>Highest sequence number accepted so far, or 0 when nothing has been accepted.</summary>
    public ulong Highest => _highest;

    /// <summary>True when <paramref name="sequenceNumber"/> is a replay or too old to judge.</summary>
    public bool IsReplay(ulong sequenceNumber)
    {
        if (!_seenAny)
        {
            return false;
        }

        if (sequenceNumber > _highest)
        {
            return false;
        }

        var delta = _highest - sequenceNumber;
        if (delta >= WindowSize)
        {
            return true;
        }

        return (_bitmap & (1UL << (int)delta)) != 0;
    }

    /// <summary>
    /// Records <paramref name="sequenceNumber"/> as accepted, sliding the window forward if needed.
    /// Returns false if it was a replay (in which case nothing is recorded).
    /// </summary>
    public bool Accept(ulong sequenceNumber)
    {
        if (IsReplay(sequenceNumber))
        {
            return false;
        }

        if (!_seenAny)
        {
            _seenAny = true;
            _highest = sequenceNumber;
            _bitmap = 1UL;
            return true;
        }

        if (sequenceNumber > _highest)
        {
            var shift = sequenceNumber - _highest;
            _bitmap = shift >= WindowSize ? 0UL : _bitmap << (int)shift;
            _bitmap |= 1UL;
            _highest = sequenceNumber;
            return true;
        }

        _bitmap |= 1UL << (int)(_highest - sequenceNumber);
        return true;
    }
}
