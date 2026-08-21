using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Keryx.Core;

namespace Keryx.Stun;

/// <summary>Sends one datagram to <paramref name="destination"/>.</summary>
/// <param name="datagram">The bytes to send. Valid only for the duration of the call.</param>
/// <param name="destination">The remote transport address.</param>
public delegate void StunDatagramSender(ReadOnlySpan<byte> datagram, IPEndPoint destination);

/// <summary>
/// A STUN Binding client with the RFC 5389 section 7.2.1 retransmission schedule.
/// </summary>
/// <remarks>
/// <para>
/// The client does not own a socket. It sends through a <see cref="StunDatagramSender"/> and is
/// fed inbound datagrams through <see cref="TryHandleDatagram"/>, so an ICE agent can run it over
/// the same socket it uses for connectivity checks and media. Use
/// <see cref="QueryAsync(IPEndPoint, StunClientOptions, IKeryxLogger, CancellationToken)"/> when a
/// throwaway socket is acceptable.
/// </para>
/// <para>Instances are safe for concurrent use; several transactions may be in flight at once.</para>
/// </remarks>
public sealed class StunClient
{
    private readonly StunDatagramSender _sender;
    private readonly StunClientOptions _options;
    private readonly IKeryxLogger _logger;
    private readonly ConcurrentDictionary<StunTransactionId, TaskCompletionSource<StunMessage>> _pending = new();

    /// <summary>Creates a client over an externally owned socket.</summary>
    /// <param name="sender">Callback that puts a datagram on the wire.</param>
    /// <param name="options">Retransmission and attribute settings; defaults if null.</param>
    /// <param name="logger">Diagnostics sink; <see cref="NullLogger"/> if null.</param>
    public StunClient(StunDatagramSender sender, StunClientOptions? options = null, IKeryxLogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(sender);
        _sender = sender;
        _options = (options ?? new StunClientOptions()).Validate();
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Offers an inbound datagram to the client.
    /// </summary>
    /// <param name="datagram">The received bytes.</param>
    /// <returns>
    /// True when the datagram was a STUN response matching an in-flight transaction and has been
    /// consumed; false when the caller should handle it (non-STUN traffic, or a STUN message that
    /// is not ours).
    /// </returns>
    public bool TryHandleDatagram(ReadOnlySpan<byte> datagram)
    {
        if (!StunMessage.LooksLikeStun(datagram) || !StunMessage.TryDecode(datagram, out var message))
        {
            return false;
        }

        if (!message.IsResponse || !_pending.TryRemove(message.TransactionId, out var pending))
        {
            return false;
        }

        if (_options.RequireValidFingerprint
            && message.HasAttribute(StunAttributeType.Fingerprint)
            && !message.ValidateFingerprint())
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping STUN response {message.TransactionId} with a bad FINGERPRINT.");
            _pending.TryAdd(message.TransactionId, pending);
            return true;
        }

        pending.TrySetResult(message);
        return true;
    }

    /// <summary>
    /// Performs a Binding transaction against <paramref name="server"/> and returns the reflexive
    /// transport address the server observed.
    /// </summary>
    /// <param name="server">The STUN server's transport address.</param>
    /// <param name="cancellationToken">Cancels the transaction.</param>
    /// <returns>The XOR-MAPPED-ADDRESS (or MAPPED-ADDRESS) from the success response.</returns>
    /// <exception cref="StunTimeoutException">No response arrived within the retransmission budget.</exception>
    /// <exception cref="StunErrorResponseException">The server answered with an error response.</exception>
    /// <exception cref="StunFormatException">The success response carried no mapped address.</exception>
    public async Task<IPEndPoint> BindingRequestAsync(IPEndPoint server, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(server);

        var request = StunMessage.CreateBindingRequest();
        if (_options.Software is { } software)
        {
            request.Add(new StunSoftwareAttribute(software));
        }

        var encoded = request.Encode(integrityKey: null, appendFingerprint: _options.AddFingerprint);
        var response = await TransactAsync(request.TransactionId, encoded, server, cancellationToken).ConfigureAwait(false);

        if (response.Class == StunClass.ErrorResponse)
        {
            var error = response.GetAttribute<StunErrorCodeAttribute>();
            throw new StunErrorResponseException(error?.Code ?? 500, error?.Reason ?? "unknown");
        }

        return response.MappedAddress
               ?? throw new StunFormatException("The STUN Binding success response carried no mapped address.");
    }

    private async Task<StunMessage> TransactAsync(
        StunTransactionId transactionId, byte[] encoded, IPEndPoint server, CancellationToken cancellationToken)
    {
        var pending = new TaskCompletionSource<StunMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pending.TryAdd(transactionId, pending))
        {
            throw new InvalidOperationException($"Transaction {transactionId} is already in flight.");
        }

        try
        {
            var rto = _options.InitialRetransmissionTimeout;
            for (var attempt = 0; attempt < _options.MaxTransmissions; attempt++)
            {
                _logger.Log(KeryxLogLevel.Trace, $"STUN Binding request {transactionId} to {server}, attempt {attempt + 1}.");
                _sender(encoded, server);

                var isFinal = attempt == _options.MaxTransmissions - 1;
                var wait = isFinal ? rto * _options.FinalWaitMultiplier : rto;
                try
                {
                    return await pending.Task.WaitAsync(wait, cancellationToken).ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                    rto += rto;
                }
            }

            throw new StunTimeoutException($"No STUN response from {server} after {_options.MaxTransmissions} transmission(s).");
        }
        finally
        {
            _pending.TryRemove(transactionId, out _);
        }
    }

    /// <summary>
    /// Convenience overload that binds a throwaway UDP socket, runs one Binding transaction and
    /// closes the socket. Prefer the instance API when the socket must be shared with ICE.
    /// </summary>
    /// <param name="server">The STUN server's transport address.</param>
    /// <param name="options">Retransmission and attribute settings; defaults if null.</param>
    /// <param name="logger">Diagnostics sink; <see cref="NullLogger"/> if null.</param>
    /// <param name="cancellationToken">Cancels the transaction.</param>
    /// <returns>The reflexive transport address the server observed.</returns>
    public static async Task<IPEndPoint> QueryAsync(
        IPEndPoint server,
        StunClientOptions? options = null,
        IKeryxLogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(server);

        using var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(
            server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));

        var client = new StunClient((datagram, destination) => socket.SendTo(datagram, destination), options, logger);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var receiveLoop = ReceiveLoopAsync(socket, client, server.AddressFamily, cts.Token);
        try
        {
            return await client.BindingRequestAsync(server, cts.Token).ConfigureAwait(false);
        }
        finally
        {
            await cts.CancelAsync().ConfigureAwait(false);
            socket.Close();
            try
            {
                await receiveLoop.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The receive loop only ever fails because the socket was closed above.
            }
        }
    }

    private static async Task ReceiveLoopAsync(
        Socket socket, StunClient client, AddressFamily family, CancellationToken cancellationToken)
    {
        var buffer = new byte[2048];
        EndPoint any = new IPEndPoint(family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        while (!cancellationToken.IsCancellationRequested)
        {
            var result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, any, cancellationToken).ConfigureAwait(false);
            client.TryHandleDatagram(buffer.AsSpan(0, result.ReceivedBytes));
        }
    }
}
