using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Keryx.Core;

namespace Keryx.Ice;

/// <summary>Receives one whole framed message reassembled from an ICE-TCP connection.</summary>
/// <param name="connection">The connection the message arrived on, so a reply can be sent back over it.</param>
/// <param name="message">The message bytes with the length prefix stripped, valid only for the duration of the call.</param>
internal delegate void IceTcpMessageHandler(IceTcpConnection connection, ReadOnlySpan<byte> message);

/// <summary>
/// One ICE-TCP connection (RFC 6544): a connected stream socket carrying STUN connectivity checks
/// and, once a pair is selected, the datagram transport that DTLS/SRTP/data ride. TCP is a byte
/// stream, not a datagram service, so every message is framed with the RFC 6544 / RFC 4571 two-byte
/// big-endian length prefix; this owns the socket, frames outbound writes, reassembles inbound
/// messages, and hands each whole message to a callback tagged with this connection.
/// </summary>
/// <remarks>
/// The connection is created either by accepting an inbound connection on the agent's passive TCP
/// listener or by dialing a remote peer's passive candidate. Either way <see cref="RemoteEndPoint"/>
/// is the socket's remote transport address, which is the key the agent routes checks and media by
/// and the source ICE validates inbound traffic against.
/// </remarks>
internal sealed class IceTcpConnection : IDisposable
{
    private const int ReceiveBufferSize = 8192;

    private readonly Socket _socket;
    private readonly NetworkStream _stream;
    private readonly IKeryxLogger _logger;
    private readonly object _writeLock = new();
    private readonly CancellationTokenSource _cts;
    private readonly byte[] _header = new byte[2];

    private byte[] _buffer = new byte[ReceiveBufferSize];
    private int _start;
    private int _end;
    private Task? _receiveLoop;
    private volatile bool _disposed;

    /// <summary>Wraps an already-connected stream socket.</summary>
    /// <param name="socket">The connected TCP socket; the connection takes ownership.</param>
    /// <param name="remoteEndPoint">The peer's transport address (the socket's normalized remote endpoint).</param>
    /// <param name="logger">Diagnostics sink.</param>
    /// <param name="agentToken">The agent's lifetime token; disposing the agent stops the receive loop.</param>
    public IceTcpConnection(Socket socket, IPEndPoint remoteEndPoint, IKeryxLogger logger, CancellationToken agentToken)
    {
        _socket = socket;
        _socket.NoDelay = true;
        _stream = new NetworkStream(socket, ownsSocket: false);
        RemoteEndPoint = remoteEndPoint;
        _logger = logger;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(agentToken);
    }

    /// <summary>The peer's transport address this connection reaches.</summary>
    public IPEndPoint RemoteEndPoint { get; }

    /// <summary>Starts the read loop that feeds reassembled messages to <paramref name="onMessage"/>.</summary>
    /// <param name="onMessage">Invoked for each whole inbound message.</param>
    /// <param name="onClosed">Invoked once when the connection ends, so the agent can forget it.</param>
    public void StartReceiving(IceTcpMessageHandler onMessage, Action<IceTcpConnection> onClosed)
        => _receiveLoop = Task.Run(() => ReceiveLoopAsync(onMessage, onClosed, _cts.Token), CancellationToken.None);

    /// <summary>
    /// Frames <paramref name="message"/> with its two-byte length and writes it. A STUN check, or a
    /// datagram from the layer above, goes out as one frame. Returns false when the connection is
    /// gone, so the caller can fall back to a retransmission rather than throw.
    /// </summary>
    public bool Send(ReadOnlySpan<byte> message)
    {
        if (_disposed)
        {
            return false;
        }

        if (message.Length > ushort.MaxValue)
        {
            throw new ArgumentException($"An ICE-TCP frame may be at most {ushort.MaxValue} bytes.", nameof(message));
        }

        lock (_writeLock)
        {
            try
            {
                BinaryPrimitives.WriteUInt16BigEndian(_header, (ushort)message.Length);
                _stream.Write(_header);
                _stream.Write(message);
                _stream.Flush();
                return true;
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
            {
                _logger.Log(KeryxLogLevel.Warning, $"Failed to write to the ICE-TCP connection to {RemoteEndPoint}.", ex);
                return false;
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cts.Cancel();

        try
        {
            _stream.Dispose();
        }
        catch (Exception)
        {
            // Being torn down; a fault on close is expected.
        }

        try
        {
            _socket.Dispose();
        }
        catch (Exception)
        {
            // Likewise.
        }

        try
        {
            _receiveLoop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // The loop only ever faults because the stream was closed above.
        }

        _cts.Dispose();
    }

    private async Task ReceiveLoopAsync(IceTcpMessageHandler onMessage, Action<IceTcpConnection> onClosed, CancellationToken cancellationToken)
    {
        var read = new byte[ReceiveBufferSize];
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var count = await _stream.ReadAsync(read, cancellationToken).ConfigureAwait(false);
                if (count == 0)
                {
                    _logger.Log(KeryxLogLevel.Debug, $"The ICE-TCP connection to {RemoteEndPoint} was closed by the peer.");
                    return;
                }

                Append(read.AsSpan(0, count));
                while (TryReadFrame(out var message))
                {
                    onMessage(this, message);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // The connection was disposed.
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            if (!_disposed)
            {
                _logger.Log(KeryxLogLevel.Debug, $"The ICE-TCP connection to {RemoteEndPoint} ended.", ex);
            }
        }
        finally
        {
            onClosed(this);
        }
    }

    private void Append(ReadOnlySpan<byte> data)
    {
        // Reclaim already-yielded space before growing, so a long-lived connection's buffer does not
        // creep upward forever.
        if (_start > 0)
        {
            var remaining = _end - _start;
            if (remaining > 0)
            {
                Array.Copy(_buffer, _start, _buffer, 0, remaining);
            }

            _start = 0;
            _end = remaining;
        }

        var required = _end + data.Length;
        if (required > _buffer.Length)
        {
            var grown = _buffer.Length * 2;
            while (grown < required)
            {
                grown *= 2;
            }

            Array.Resize(ref _buffer, grown);
        }

        data.CopyTo(_buffer.AsSpan(_end));
        _end += data.Length;
    }

    /// <summary>
    /// Yields the next whole framed message once its two-byte length prefix and full payload have
    /// arrived. The returned span views the internal buffer and is valid only until the next read.
    /// </summary>
    private bool TryReadFrame(out ReadOnlySpan<byte> message)
    {
        var available = _end - _start;
        if (available < 2)
        {
            message = default;
            return false;
        }

        var length = BinaryPrimitives.ReadUInt16BigEndian(_buffer.AsSpan(_start));
        if (available < 2 + length)
        {
            message = default;
            return false;
        }

        message = _buffer.AsSpan(_start + 2, length);
        _start += 2 + length;
        return true;
    }
}
