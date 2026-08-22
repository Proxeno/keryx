namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// Remembers the send time and size of recently sent packets, keyed by their transport-wide sequence
/// number, so transport-cc feedback can be paired with the local send clock to recover one-way delay
/// variation.
/// </summary>
/// <remarks>
/// Backed by a power-of-two ring indexed by the low bits of the sequence number, so it allocates
/// nothing per packet and silently drops entries older than its capacity — feedback always names
/// recent sequence numbers, so an evicted entry is one the estimator no longer needs.
/// </remarks>
public sealed class SendTimeHistory
{
    /// <summary>The default number of packets retained.</summary>
    public const int DefaultCapacity = 2048;

    private readonly int _mask;
    private readonly int[] _sequenceNumbers;
    private readonly long[] _sendTimes;
    private readonly int[] _sizes;

    /// <summary>Creates a history.</summary>
    /// <param name="capacity">
    /// The number of packets to retain; rounded up to a power of two. Must be positive.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="capacity"/> is not positive.</exception>
    public SendTimeHistory(int capacity = DefaultCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);

        var rounded = 1;
        while (rounded < capacity)
        {
            rounded <<= 1;
        }

        _mask = rounded - 1;
        _sequenceNumbers = new int[rounded];
        _sendTimes = new long[rounded];
        _sizes = new int[rounded];
        Array.Fill(_sequenceNumbers, -1);
    }

    /// <summary>Records a sent packet, overwriting any older entry that shares its ring slot.</summary>
    /// <param name="sequenceNumber">The transport-wide sequence number.</param>
    /// <param name="sendTimeMicroseconds">The local send time, in microseconds.</param>
    /// <param name="sizeBytes">The packet's size on the wire, in bytes.</param>
    public void Add(ushort sequenceNumber, long sendTimeMicroseconds, int sizeBytes)
    {
        var slot = sequenceNumber & _mask;
        _sequenceNumbers[slot] = sequenceNumber;
        _sendTimes[slot] = sendTimeMicroseconds;
        _sizes[slot] = sizeBytes;
    }

    /// <summary>Looks up a sent packet by its transport-wide sequence number.</summary>
    /// <param name="sequenceNumber">The sequence number to resolve.</param>
    /// <param name="sendTimeMicroseconds">On success, the recorded send time in microseconds.</param>
    /// <param name="sizeBytes">On success, the recorded size in bytes.</param>
    /// <returns><see langword="true"/> when the packet is still retained.</returns>
    public bool TryGet(ushort sequenceNumber, out long sendTimeMicroseconds, out int sizeBytes)
    {
        var slot = sequenceNumber & _mask;
        if (_sequenceNumbers[slot] == sequenceNumber)
        {
            sendTimeMicroseconds = _sendTimes[slot];
            sizeBytes = _sizes[slot];
            return true;
        }

        sendTimeMicroseconds = 0;
        sizeBytes = 0;
        return false;
    }
}
