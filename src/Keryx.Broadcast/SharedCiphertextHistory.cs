namespace Keryx.Broadcast;

/// <summary>
/// The one shared retransmission history for a <see cref="SharedKeyBroadcastTier"/> (spec §5.2): a
/// bounded ring of recently-sent broadcast ciphertexts, keyed by broadcast sequence number. Because
/// every viewer received byte-identical ciphertext, one buffer serves every viewer's NACK — a resend is
/// the verbatim stored ciphertext, sent only to the viewer that asked. Cheaper than per-viewer RTX and
/// with no per-viewer state.
/// </summary>
/// <remarks>Not thread-safe; driven from the tier's single send thread alongside <c>Fanout</c>.</remarks>
internal sealed class SharedCiphertextHistory
{
    private readonly byte[][] _buffers;
    private readonly int[] _lengths;
    private readonly ushort[] _sequenceNumbers;
    private readonly bool[] _valid;
    private readonly Dictionary<ushort, int> _slotBySequence;
    private int _cursor;

    internal SharedCiphertextHistory(int depth, int maxCiphertextSize)
    {
        _buffers = new byte[depth][];
        for (var i = 0; i < depth; i++)
        {
            _buffers[i] = new byte[maxCiphertextSize];
        }

        _lengths = new int[depth];
        _sequenceNumbers = new ushort[depth];
        _valid = new bool[depth];
        _slotBySequence = new Dictionary<ushort, int>(depth);
    }

    /// <summary>Stores one ciphertext under its broadcast sequence number, evicting the oldest slot.</summary>
    internal void Record(ushort sequenceNumber, ReadOnlySpan<byte> ciphertext)
    {
        var slot = _cursor;
        _cursor = (_cursor + 1) % _buffers.Length;

        // Evict whatever this ring slot held, but only unmap the sequence if it still points here (a later
        // write of the same sequence number could have moved its mapping to another slot).
        if (_valid[slot] && _slotBySequence.TryGetValue(_sequenceNumbers[slot], out var mapped) && mapped == slot)
        {
            _slotBySequence.Remove(_sequenceNumbers[slot]);
        }

        ciphertext.CopyTo(_buffers[slot]);
        _lengths[slot] = ciphertext.Length;
        _sequenceNumbers[slot] = sequenceNumber;
        _valid[slot] = true;
        _slotBySequence[sequenceNumber] = slot;
    }

    /// <summary>Retrieves a stored ciphertext by broadcast sequence number, if still in the ring.</summary>
    internal bool TryGet(ushort sequenceNumber, out ReadOnlyMemory<byte> ciphertext)
    {
        if (_slotBySequence.TryGetValue(sequenceNumber, out var slot) && _valid[slot] && _sequenceNumbers[slot] == sequenceNumber)
        {
            ciphertext = _buffers[slot].AsMemory(0, _lengths[slot]);
            return true;
        }

        ciphertext = default;
        return false;
    }
}
