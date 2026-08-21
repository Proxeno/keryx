using System.Threading.Channels;
using Keryx.Core;

namespace Keryx.Dtls.Tests;

/// <summary>
/// An in-memory <see cref="IDatagramTransport"/> pair used to run two <see cref="DtlsTransport"/>
/// instances against each other. Delivery is asynchronous (through a channel and a pump task) so
/// that a synchronous send never re-enters the sender's state machine, which is exactly how a real
/// socket behaves.
/// </summary>
internal sealed class LoopbackDatagramTransport : IDatagramTransport, IDisposable
{
    private readonly Channel<byte[]> _incoming = Channel.CreateUnbounded<byte[]>(
        new UnboundedChannelOptions { SingleReader = true });

    private readonly CancellationTokenSource _cts = new();
    private readonly Task _pump;
    private LoopbackDatagramTransport? _peer;
    private int _sentCount;

    private LoopbackDatagramTransport(string name)
    {
        Name = name;
        _pump = Task.Run(PumpAsync);
    }

    public event DatagramReceivedHandler? OnReceived;

    public string Name { get; }

    public int MaxDatagramSize { get; set; } = 1400;

    /// <summary>Number of datagrams handed to <see cref="Send"/>, including dropped ones.</summary>
    public int SentCount => Volatile.Read(ref _sentCount);

    /// <summary>Number of datagrams actually delivered to the peer.</summary>
    public int DeliveredCount { get; private set; }

    /// <summary>
    /// Called with (datagram, zero-based send index); returning true drops the datagram, which is
    /// how the lossy-network tests force retransmission.
    /// </summary>
    public Func<byte[], int, bool>? DropOutbound { get; set; }

    /// <summary>Rewrites a datagram before delivery; returning null drops it.</summary>
    public Func<byte[], int, byte[]?>? TransformOutbound { get; set; }

    public static (LoopbackDatagramTransport Left, LoopbackDatagramTransport Right) CreatePair()
    {
        var left = new LoopbackDatagramTransport("left");
        var right = new LoopbackDatagramTransport("right");
        left._peer = right;
        right._peer = left;
        return (left, right);
    }

    public void Send(ReadOnlySpan<byte> datagram)
    {
        var index = Interlocked.Increment(ref _sentCount) - 1;
        var copy = datagram.ToArray();

        if (DropOutbound?.Invoke(copy, index) == true)
        {
            return;
        }

        if (TransformOutbound is not null)
        {
            var transformed = TransformOutbound(copy, index);
            if (transformed is null)
            {
                return;
            }

            copy = transformed;
        }

        DeliveredCount++;
        _peer?._incoming.Writer.TryWrite(copy);
    }

    public void Dispose()
    {
        _incoming.Writer.TryComplete();
        _cts.Cancel();
        try
        {
            _pump.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException)
        {
            // The pump was cancelled.
        }

        _cts.Dispose();
    }

    private async Task PumpAsync()
    {
        try
        {
            await foreach (var datagram in _incoming.Reader.ReadAllAsync(_cts.Token).ConfigureAwait(false))
            {
                try
                {
                    OnReceived?.Invoke(datagram);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[{Name}] receive handler threw: {ex}");
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected on dispose.
        }
    }
}
