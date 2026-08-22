using System.Collections.Concurrent;
using Keryx.Core;

namespace Keryx.Sctp.Tests;

/// <summary>
/// An in-memory <see cref="IDatagramTransport"/> pair standing in for the DTLS application-data
/// stream, with hooks for dropping and reordering datagrams.
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
    private byte[]? _held;
    private long _heldAtTicks;
    private int _dropData;
    private bool _reorderData;
    private int _sent;
    private int _dropped;

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

    /// <summary>Discards the next <paramref name="count"/> datagrams whose first chunk is DATA.</summary>
    public void DropNextDataDatagrams(int count)
    {
        lock (_gate)
        {
            _dropData = count;
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

        lock (_gate)
        {
            if (isData && _dropData > 0)
            {
                _dropData--;
                Interlocked.Increment(ref _dropped);
                return;
            }

            if (isData && _reorderData)
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

    /// <summary>True when any chunk in the datagram is a DATA chunk.</summary>
    private static bool ContainsData(byte[] packet)
    {
        var offset = 12;
        while (packet.Length - offset >= 4)
        {
            if (packet[offset] == (byte)SctpChunkType.Data)
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
