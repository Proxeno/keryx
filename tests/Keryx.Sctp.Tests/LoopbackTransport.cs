using System.Buffers.Binary;
using System.Collections.Concurrent;
using Keryx.Core;

namespace Keryx.Sctp.Tests;

/// <summary>
/// The datagram-mangling fault modes <see cref="LoopbackTransport"/> can inject into a live
/// association's data path, standing in for an on-path corrupter or a lossy/flaky link.
/// </summary>
public enum DatagramCorruption
{
    /// <summary>Flip a handful of random bits in the chunk region. Leaves the CRC-32C stale, so the
    /// receiver must reject the packet as malformed.</summary>
    BitFlip,

    /// <summary>Cut the datagram off at a random earlier length (header-sized down to mid-chunk).</summary>
    Truncate,

    /// <summary>Deliver the datagram unchanged, then deliver an identical copy — a duplicated packet.</summary>
    Duplicate,

    /// <summary>Rewrite the first DATA chunk's length field to an invalid value and re-stamp a valid
    /// CRC-32C, so the packet passes the checksum gate and the deeper chunk parser must reject it.</summary>
    BadChunkLength,

    /// <summary>Rewrite the first DATA chunk's TSN to a wild value and re-stamp a valid CRC-32C, so a
    /// well-formed but semantically bogus TSN reaches the association's data-handling path.</summary>
    BadTsn,

    /// <summary>Overwrite the checksum field with a deliberately wrong value, so the receiver must
    /// reject the packet at the CRC-32C gate.</summary>
    BadChecksum,
}

/// <summary>
/// An in-memory <see cref="IDatagramTransport"/> pair standing in for the DTLS application-data
/// stream, with hooks for dropping, reordering and corrupting datagrams.
/// </summary>
/// <remarks>
/// Delivery is asynchronous through a per-endpoint queue and pump thread, so a send never re-enters
/// the sender's association on the same stack — the same shape as a real network.
/// </remarks>
internal sealed class LoopbackTransport : IDatagramTransport, IDisposable
{
    private readonly BlockingCollection<byte[]> _inbox = new();
    private readonly Thread _pump;
    private readonly object _gate = new();
    private readonly Timer _releaseTimer;

    // Deterministic PRNG for bit-flip positions and truncation lengths, so a corruption run
    // reproduces byte-for-byte in CI. Only ever touched under _gate.
    private readonly Random _corruptRng = new(0x0FA17);
    private byte[]? _held;
    private long _heldAtTicks;
    private int _dropData;
    private bool _reorderData;
    private int _corruptData;
    private DatagramCorruption _corruptMode;
    private int _sent;
    private int _dropped;
    private int _corrupted;

    public LoopbackTransport(string name)
    {
        Name = name;
        _pump = new Thread(Pump) { IsBackground = true, Name = $"loopback-{name}" };
        _pump.Start();
        _releaseTimer = new Timer(_ => ReleaseStale(), null, 20, 20);
    }

    public event DatagramReceivedHandler? OnReceived;

    public string Name { get; }

    public int MaxDatagramSize { get; set; } = 1200;

    public LoopbackTransport? Peer { get; set; }

    /// <summary>Total datagrams handed to the peer.</summary>
    public int SentDatagrams => Volatile.Read(ref _sent);

    /// <summary>Total datagrams discarded by <see cref="DropNextDataDatagrams"/>.</summary>
    public int DroppedDatagrams => Volatile.Read(ref _dropped);

    /// <summary>Total datagrams mangled by <see cref="CorruptNextDataDatagrams"/>.</summary>
    public int CorruptedDatagrams => Volatile.Read(ref _corrupted);

    /// <summary>Discards the next <paramref name="count"/> datagrams whose first chunk is DATA.</summary>
    public void DropNextDataDatagrams(int count)
    {
        lock (_gate)
        {
            _dropData = count;
        }
    }

    /// <summary>
    /// Applies <paramref name="mode"/> to the next <paramref name="count"/> DATA-bearing datagrams as
    /// they are sent, standing in for on-path corruption of a live association. Non-DATA datagrams
    /// (the handshake, SACKs, heartbeats) are left intact so corruption targets user-data delivery.
    /// Corruption bypasses the reorder hook so the two features stay independent.
    /// </summary>
    public void CorruptNextDataDatagrams(int count, DatagramCorruption mode)
    {
        lock (_gate)
        {
            _corruptData = count;
            _corruptMode = mode;
        }
    }

    /// <summary>
    /// When enabled, DATA-bearing datagrams are delivered in swapped pairs: the first is held until
    /// the second is sent, and then the two are delivered second-then-first. A held datagram is
    /// released after 60 ms even if no partner arrives, so nothing is ever silently lost.
    /// </summary>
    public void SetDataReordering(bool enabled)
    {
        byte[]? release = null;
        lock (_gate)
        {
            _reorderData = enabled;
            if (!enabled)
            {
                release = _held;
                _held = null;
            }
        }

        if (release is not null)
        {
            Deliver(release);
        }
    }

    public void Send(ReadOnlySpan<byte> datagram)
    {
        var copy = datagram.ToArray();
        var isData = ContainsData(copy);
        byte[]? first = null;
        byte[]? second = null;
        byte[]? duplicate = null;

        lock (_gate)
        {
            if (isData && _dropData > 0)
            {
                _dropData--;
                Interlocked.Increment(ref _dropped);
                return;
            }

            if (isData && _corruptData > 0)
            {
                _corruptData--;
                Interlocked.Increment(ref _corrupted);
                if (_corruptMode == DatagramCorruption.Duplicate)
                {
                    duplicate = (byte[])copy.Clone();
                }
                else
                {
                    copy = Corrupt(copy, _corruptMode, _corruptRng);
                }
            }
            else if (isData && _reorderData)
            {
                if (_held is null)
                {
                    _held = copy;
                    _heldAtTicks = Environment.TickCount64;
                    return;
                }

                first = copy;
                second = _held;
                _held = null;
            }
        }

        if (first is not null && second is not null)
        {
            Deliver(first);
            Deliver(second);
            return;
        }

        Deliver(copy);
        if (duplicate is not null)
        {
            Deliver(duplicate);
        }
    }

    public void Dispose()
    {
        _releaseTimer.Dispose();
        _inbox.CompleteAdding();
        _pump.Join(TimeSpan.FromSeconds(2));
        _inbox.Dispose();
    }

    /// <summary>Creates a connected pair of transports.</summary>
    public static (LoopbackTransport A, LoopbackTransport B) CreatePair()
    {
        var a = new LoopbackTransport("A");
        var b = new LoopbackTransport("B");
        a.Peer = b;
        b.Peer = a;
        return (a, b);
    }

    /// <summary>True when any chunk in the datagram is a DATA or I-DATA chunk.</summary>
    private static bool ContainsData(byte[] packet)
    {
        var offset = 12;
        while (packet.Length - offset >= 4)
        {
            if (packet[offset] == (byte)SctpChunkType.Data || packet[offset] == (byte)SctpChunkType.IData)
            {
                return true;
            }

            var length = (packet[offset + 2] << 8) | packet[offset + 3];
            if (length < 4)
            {
                return false;
            }

            offset += (length + 3) & ~3;
        }

        return false;
    }

    /// <summary>Offset of the first DATA/I-DATA chunk in the packet, or -1 if none is present.</summary>
    private static int FindDataChunk(byte[] packet)
    {
        var offset = 12;
        while (packet.Length - offset >= 4)
        {
            if (packet[offset] == (byte)SctpChunkType.Data || packet[offset] == (byte)SctpChunkType.IData)
            {
                return offset;
            }

            var length = (packet[offset + 2] << 8) | packet[offset + 3];
            if (length < 4)
            {
                return -1;
            }

            offset += (length + 3) & ~3;
        }

        return -1;
    }

    /// <summary>Applies a single (non-<see cref="DatagramCorruption.Duplicate"/>) corruption to a copy
    /// of a DATA-bearing datagram, returning the mangled bytes.</summary>
    private static byte[] Corrupt(byte[] packet, DatagramCorruption mode, Random rng)
    {
        switch (mode)
        {
            case DatagramCorruption.BitFlip:
                // Flip a few bits in the chunk region (past the common header). The CRC-32C is left
                // stale, so a correct receiver rejects the packet as malformed.
                var flips = 1 + rng.Next(4);
                for (var n = 0; n < flips && packet.Length > 12; n++)
                {
                    var index = 12 + rng.Next(packet.Length - 12);
                    packet[index] ^= (byte)(1 << rng.Next(8));
                }

                return packet;

            case DatagramCorruption.Truncate:
                // Cut anywhere from a header-sized stub down to one byte short of the full length.
                var cut = 4 + rng.Next(packet.Length - 4);
                return packet[..cut];

            case DatagramCorruption.BadChunkLength:
            {
                var data = FindDataChunk(packet);
                if (data >= 0)
                {
                    // A length below the 4-byte minimum, a length claiming far more than is present,
                    // or zero — all of which the chunk parser must reject.
                    var bogus = rng.Next(3) switch { 0 => (ushort)0, 1 => (ushort)3, _ => (ushort)0xFFFF };
                    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(data + 2, 2), bogus);
                }

                return ReStampChecksum(packet);
            }

            case DatagramCorruption.BadTsn:
            {
                var data = FindDataChunk(packet);
                if (data >= 0 && packet.Length - data >= 8)
                {
                    // Shove the TSN far out of the peer's window. Well-formed, valid checksum, but
                    // names data the sender never transmitted.
                    var tsn = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(data + 4, 4));
                    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(data + 4, 4), unchecked(tsn + 0x40000000u));
                }

                return ReStampChecksum(packet);
            }

            case DatagramCorruption.BadChecksum:
            {
                // Store a value that cannot match the true CRC-32C, forcing rejection at the gate.
                var correct = SctpPacket.ComputeChecksum(packet);
                BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(SctpPacket.ChecksumOffset, 4), correct ^ 0xFFFFFFFFu);
                return packet;
            }

            default:
                return packet;
        }
    }

    /// <summary>Writes the correct CRC-32C back into a mutated packet so it passes the checksum gate
    /// and the mangled chunk itself is what the receiver has to cope with.</summary>
    private static byte[] ReStampChecksum(byte[] packet)
    {
        if (packet.Length >= SctpPacket.CommonHeaderLength)
        {
            var checksum = SctpPacket.ComputeChecksum(packet);
            BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(SctpPacket.ChecksumOffset, 4), checksum);
        }

        return packet;
    }

    private void ReleaseStale()
    {
        byte[]? release = null;
        lock (_gate)
        {
            if (_held is not null && Environment.TickCount64 - _heldAtTicks >= 60)
            {
                release = _held;
                _held = null;
            }
        }

        if (release is not null)
        {
            Deliver(release);
        }
    }

    private void Deliver(byte[] datagram)
    {
        Interlocked.Increment(ref _sent);
        var peer = Peer;
        if (peer is null)
        {
            return;
        }

        try
        {
            peer._inbox.Add(datagram);
        }
        catch (InvalidOperationException)
        {
            // Peer disposed mid-test.
        }
    }

    private void Pump()
    {
        try
        {
            foreach (var datagram in _inbox.GetConsumingEnumerable())
            {
                OnReceived?.Invoke(datagram);
            }
        }
        catch (ObjectDisposedException)
        {
        }
        catch (InvalidOperationException)
        {
        }
    }
}
