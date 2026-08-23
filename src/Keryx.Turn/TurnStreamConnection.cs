using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using Keryx.Core;

namespace Keryx.Turn;

/// <summary>Receives one whole STUN or ChannelData message reassembled from the TURN TCP stream.</summary>
/// <param name="message">The message bytes, valid only for the duration of the call.</param>
internal delegate void TurnStreamMessageHandler(ReadOnlySpan<byte> message);

/// <summary>
/// The client-to-server leg of a TURN allocation carried over TCP, optionally wrapped in TLS
/// (RFC 5766 section 2.1). It owns the connection, frames outbound STUN/ChannelData writes,
/// reassembles inbound messages from the byte stream, and hands each whole message to a callback -
/// the seam a <see cref="TurnClient"/> otherwise fills with a UDP socket it does not own.
/// </summary>
internal sealed class TurnStreamConnection : IDisposable
{
    private readonly IPEndPoint _server;
    private readonly TurnClientTransport _transport;
    private readonly string _tlsServerName;
    private readonly RemoteCertificateValidationCallback? _certificateValidation;
    private readonly IKeryxLogger _logger;
    private readonly TurnStreamReassembler _reassembler = new();
    private readonly object _writeLock = new();
    private readonly CancellationTokenSource _cts = new();

    private Socket? _socket;
    private Stream? _stream;
    private Task? _receiveLoop;
    private TurnStreamMessageHandler? _onMessage;
    private volatile bool _disposed;

    public TurnStreamConnection(
        IPEndPoint server,
        TurnClientTransport transport,
        string? tlsServerName,
        RemoteCertificateValidationCallback? certificateValidation,
        IKeryxLogger logger)
    {
        _server = server;
        _transport = transport;
        _tlsServerName = string.IsNullOrWhiteSpace(tlsServerName) ? server.Address.ToString() : tlsServerName;
        _certificateValidation = certificateValidation;
        _logger = logger;
    }

    /// <summary>Opens the TCP connection and, for <see cref="TurnClientTransport.Tls"/>, the TLS handshake.</summary>
    public async Task ConnectAsync(CancellationToken cancellationToken)
    {
        var socket = new Socket(_server.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            socket.NoDelay = true;
            await socket.ConnectAsync(_server, cancellationToken).ConfigureAwait(false);

            Stream stream = new NetworkStream(socket, ownsSocket: false);
            if (_transport == TurnClientTransport.Tls)
            {
                // Standard chain-and-name validation unless the caller supplied a callback (for
                // pinning, or a private CA); validation is never simply switched off here.
                var tls = new SslStream(stream, leaveInnerStreamOpen: false, _certificateValidation);
                try
                {
                    await tls.AuthenticateAsClientAsync(
                        new SslClientAuthenticationOptions
                        {
                            TargetHost = _tlsServerName,
                            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        },
                        cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    await tls.DisposeAsync().ConfigureAwait(false);
                    throw;
                }

                stream = tls;
            }

            _socket = socket;
            _stream = stream;
            _logger.Log(KeryxLogLevel.Debug, $"TURN {_transport} connection to {_server} established.");
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>Starts the read loop that feeds reassembled messages to <paramref name="onMessage"/>.</summary>
    public void StartReceiving(TurnStreamMessageHandler onMessage)
    {
        _onMessage = onMessage;
        _receiveLoop = Task.Run(() => ReceiveLoopAsync(_cts.Token), CancellationToken.None);
    }

    /// <summary>
    /// Writes one already-encoded STUN or ChannelData message to the server, adding the four-byte
    /// ChannelData padding TCP requires (RFC 5766 section 11.5). The destination is ignored - a
    /// stream connection only ever talks to its one server - so this matches
    /// <see cref="Keryx.Stun.StunDatagramSender"/>.
    /// </summary>
    public void Send(ReadOnlySpan<byte> message, IPEndPoint destination)
    {
        _ = destination;
        if (_disposed)
        {
            return;
        }

        var stream = _stream;
        if (stream is null)
        {
            throw new InvalidOperationException("The TURN TCP connection has not been established.");
        }

        // STUN messages are already a multiple of four bytes; ChannelData is padded up. Padding the
        // whole framed message to a four-byte boundary is therefore correct for both.
        var padded = (message.Length + 3) & ~3;
        var pad = padded - message.Length;

        lock (_writeLock)
        {
            stream.Write(message);
            if (pad > 0)
            {
                Span<byte> padding = stackalloc byte[4];
                padding.Clear();
                stream.Write(padding[..pad]);
            }

            stream.Flush();
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
            _stream?.Dispose();
        }
        catch (Exception)
        {
            // The stream is being torn down; a fault on close is expected.
        }

        try
        {
            _socket?.Dispose();
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

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        var stream = _stream!;
        var buffer = new byte[8192];
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    _logger.Log(KeryxLogLevel.Debug, $"The TURN {_transport} connection to {_server} was closed by the server.");
                    return;
                }

                _reassembler.Append(buffer.AsSpan(0, read));
                while (_reassembler.TryReadMessage(out var message))
                {
                    _onMessage?.Invoke(message);
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
                _logger.Log(KeryxLogLevel.Warning, $"The TURN {_transport} connection to {_server} failed; the allocation is lost.", ex);
            }
        }
        catch (TurnStreamException ex)
        {
            _logger.Log(KeryxLogLevel.Warning, $"The TURN {_transport} connection to {_server} desynchronised and was dropped.", ex);
        }
    }
}
