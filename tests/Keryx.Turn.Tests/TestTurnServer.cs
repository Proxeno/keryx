using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Keryx.Stun;
using Keryx.Turn;

namespace Keryx.Turn.Tests;

/// <summary>
/// A deliberately small but genuine TURN server (RFC 8656) over UDP loopback: long-term
/// authentication with a 401 challenge, one allocation on a real second socket, permissions,
/// channel bindings, ChannelData and Send/Data indications.
/// </summary>
/// <remarks>
/// It exists so the relay can be *observed*: every relayed datagram is counted, the relayed
/// address is a socket the server really owns and really sends from, and permissions are enforced,
/// so a test can prove a packet went through the allocation rather than taking a host shortcut.
/// </remarks>
internal sealed class TestTurnServer : IDisposable
{
    private readonly Socket _control;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _lock = new();
    private readonly Dictionary<IPAddress, DateTimeOffset> _permissions = [];
    private readonly Dictionary<ushort, IPEndPoint> _channels = [];
    private readonly Dictionary<IPEndPoint, ushort> _channelsByPeer = [];
    private readonly List<Task> _loops = [];

    private Socket? _relay;
    private IPEndPoint? _client;
    private string _nonce = NewNonce();
    private int _noncesIssued;
    private bool _disposed;

    public TestTurnServer(string username = "keryx", string password = "keryxpass", string realm = "keryx.test")
    {
        Username = username;
        Password = password;
        Realm = realm;

        _control = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _control.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        EndPoint = (IPEndPoint)_control.LocalEndPoint!;
        lock (_lock)
        {
            _loops.Add(Task.Run(() => ControlLoopAsync(_cts.Token)));
        }
    }

    public string Username { get; }

    public string Password { get; }

    public string Realm { get; }

    /// <summary>The server's transport address.</summary>
    public IPEndPoint EndPoint { get; }

    /// <summary>The lifetime handed back in Allocate and Refresh responses.</summary>
    public TimeSpan GrantedLifetime { get; set; } = TimeSpan.FromSeconds(StunLifetimeAttribute.DefaultAllocationSeconds);

    /// <summary>
    /// When positive, the Nth authenticated request (1-based) is answered 438 Stale Nonce with a
    /// fresh nonce instead of being processed, exercising RFC 8489 section 9.2.5's retry.
    /// </summary>
    public int StaleNonceOnRequest { get; set; }

    /// <summary>False to relay from any peer, so a test can show what permissions are actually for.</summary>
    public bool EnforcePermissions { get; set; } = true;

    /// <summary>
    /// True to prefix the nonce with RFC 8489 section 9.2's "obMatJos2" cookie, set the
    /// password-algorithms Security Feature bit, and carry a PASSWORD-ALGORITHMS attribute (built
    /// from <see cref="OfferedPasswordAlgorithms"/>) on every challenge.
    /// </summary>
    public bool AdvertisePasswordAlgorithms { get; set; }

    /// <summary>
    /// The RFC 8489 password algorithms offered in PASSWORD-ALGORITHMS, in preferential order, when
    /// <see cref="AdvertisePasswordAlgorithms"/> is set. Defaults to SHA-256 preferred over MD5, so a
    /// client that implements the negotiation picks SHA-256.
    /// </summary>
    public IReadOnlyList<StunPasswordAlgorithm> OfferedPasswordAlgorithms { get; set; } =
        [StunPasswordAlgorithm.Sha256, StunPasswordAlgorithm.Md5];

    /// <summary>When positive, every authenticated Allocate is refused with this error code.</summary>
    public int RefuseAllocationsWith { get; set; }

    /// <summary>
    /// True to always grant an IPv4 relay regardless of what REQUESTED-ADDRESS-FAMILY asked for - a
    /// double for a server that mishandles RFC 8656 section 18.6, so a test can prove the client
    /// notices a family it did not ask for.
    /// </summary>
    public bool IgnoreRequestedAddressFamily { get; set; }

    /// <summary>
    /// The REQUESTED-ADDRESS-FAMILY the last Allocate carried, or null when the request carried
    /// none at all (RFC 8656 section 18.6).
    /// </summary>
    public AddressFamily? LastAllocateRequestedFamily { get; private set; }

    /// <summary>The relayed transport address handed out by the last Allocate, if any.</summary>
    public IPEndPoint? RelayedEndPoint
    {
        get
        {
            lock (_lock)
            {
                return _relay?.LocalEndPoint as IPEndPoint;
            }
        }
    }

    public int UnauthenticatedAllocates;
    public int AuthenticatedAllocates;
    public int RefreshRequests;
    public int Releases;
    public int CreatePermissionRequests;
    public int ChannelBindRequests;
    public int StaleNonceResponses;

    /// <summary>Datagrams the client handed to the relay for a peer (ChannelData or Send indication).</summary>
    public int RelayedToPeer;

    /// <summary>Datagrams a peer sent to the relayed address that were forwarded to the client.</summary>
    public int RelayedToClient;

    /// <summary>Datagrams dropped because no permission existed for the sender.</summary>
    public int DroppedUnpermitted;

    /// <summary>Datagrams the client sent as ChannelData rather than as a Send indication.</summary>
    public int ChannelDataFromClient;

    /// <summary>Datagrams forwarded to the client as ChannelData rather than as a Data indication.</summary>
    public int ChannelDataToClient;

    public IReadOnlyCollection<IPAddress> Permissions
    {
        get
        {
            lock (_lock)
            {
                return [.. _permissions.Keys];
            }
        }
    }

    public IReadOnlyDictionary<ushort, IPEndPoint> Channels
    {
        get
        {
            lock (_lock)
            {
                return new Dictionary<ushort, IPEndPoint>(_channels);
            }
        }
    }

    public TurnServerOptions ToOptions() => new(EndPoint, Username, Password);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cts.Cancel();
        _control.Close();
        Task[] loops;
        lock (_lock)
        {
            _relay?.Close();
            loops = [.. _loops];
        }

        try
        {
            Task.WhenAll(loops).Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // The loops only ever fault because their socket was closed above.
        }

        _control.Dispose();
        _relay?.Dispose();
        _cts.Dispose();
    }

    private string NewNonceValue()
    {
        var random = Convert.ToHexString(RandomNumberGenerator.GetBytes(12));

        // RFC 8489 section 9.2: "obMatJos2" plus four base64 characters carrying 24 feature bits;
        // "gAAA" is bit 0 - password algorithms - set.
        return AdvertisePasswordAlgorithms ? "obMatJos2gAAA" + random : random;
    }

    private static string NewNonce() => Convert.ToHexString(RandomNumberGenerator.GetBytes(12));

    private async Task ControlLoopAsync(CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        EndPoint any = new IPEndPoint(IPAddress.Any, 0);
        while (!cancellationToken.IsCancellationRequested)
        {
            SocketReceiveFromResult result;
            try
            {
                result = await _control.ReceiveFromAsync(buffer, SocketFlags.None, any, cancellationToken);
            }
            catch (Exception)
            {
                return;
            }

            var datagram = buffer.AsSpan(0, result.ReceivedBytes);
            var from = (IPEndPoint)result.RemoteEndPoint;

            if (TurnChannelData.TryDecode(datagram, out var channelNumber, out var payload))
            {
                Interlocked.Increment(ref ChannelDataFromClient);
                RelayToPeerByChannel(channelNumber, payload);
                continue;
            }

            if (!StunMessage.TryDecode(datagram, out var message))
            {
                continue;
            }

            HandleMessage(message, datagram.ToArray(), from);
        }
    }

    private void HandleMessage(StunMessage message, byte[] raw, IPEndPoint from)
    {
        if (message.Class == StunClass.Indication && message.Method == StunMethod.Send)
        {
            var peer = message.GetAttribute<StunXorPeerAddressAttribute>()?.EndPoint;
            var data = message.GetAttribute<StunDataAttribute>();
            if (peer is not null && data is not null)
            {
                RelayToPeer(peer, data.Value);
            }

            return;
        }

        if (message.Class != StunClass.Request)
        {
            return;
        }

        var hasIntegrity = message.HasAttribute(StunAttributeType.MessageIntegrity)
            || message.HasAttribute(StunAttributeType.MessageIntegritySha256);
        if (message.Method == StunMethod.Allocate && !hasIntegrity)
        {
            Interlocked.Increment(ref UnauthenticatedAllocates);
            SendChallenge(message, from, StunErrorCodeAttribute.Unauthorized, "Unauthorized");
            return;
        }

        // RFC 8489 section 9.2.4: once the nonce we issued advertised password algorithms, a
        // request carrying PASSWORD-ALGORITHM is keyed and signed accordingly; anything else - no
        // PASSWORD-ALGORITHM, or the feature never advertised - is processed as plain MD5/MESSAGE-INTEGRITY.
        var requestAlgorithm = message.GetAttribute<StunPasswordAlgorithmAttribute>();
        var useSha256 = AdvertisePasswordAlgorithms && requestAlgorithm is not null;
        var algorithm = useSha256 ? (StunPasswordAlgorithm)requestAlgorithm!.Algorithm : StunPasswordAlgorithm.Md5;

        var key = StunCredentials.LongTermKey(Username, Realm, Password, algorithm);
        var integrityValid = useSha256
            ? StunMessage.ValidateMessageIntegritySha256(raw, key)
            : StunMessage.ValidateMessageIntegrity(raw, key);
        if (message.Username != Username || !integrityValid)
        {
            SendChallenge(message, from, StunErrorCodeAttribute.Unauthorized, "Unauthorized");
            return;
        }

        string expectedNonce;
        lock (_lock)
        {
            expectedNonce = _nonce;
        }

        var staleOn = StaleNonceOnRequest;
        var shouldExpire = staleOn > 0 && Interlocked.Increment(ref _noncesIssued) == staleOn;
        if (message.Nonce != expectedNonce || shouldExpire)
        {
            Interlocked.Increment(ref StaleNonceResponses);
            lock (_lock)
            {
                _nonce = NewNonceValue();
            }

            SendChallenge(message, from, StunErrorCodeAttribute.StaleNonce, "Stale Nonce");
            return;
        }

        switch (message.Method)
        {
            case StunMethod.Allocate:
                HandleAllocate(message, from, key, useSha256);
                break;
            case StunMethod.Refresh:
                HandleRefresh(message, from, key, useSha256);
                break;
            case StunMethod.CreatePermission:
                HandleCreatePermission(message, from, key, useSha256);
                break;
            case StunMethod.ChannelBind:
                HandleChannelBind(message, from, key, useSha256);
                break;
            default:
                Send(StunMessage.CreateErrorResponse(message, StunErrorCodeAttribute.BadRequest, "Bad Request"), from, key, useSha256);
                break;
        }
    }

    private void HandleAllocate(StunMessage request, IPEndPoint from, byte[] key, bool useSha256)
    {
        Interlocked.Increment(ref AuthenticatedAllocates);

        // RFC 8656 section 18.6: absent, the client gets the server's default (IPv4); present, the
        // relayed address comes from the named family. Recorded so a test can assert on what the
        // client actually put on the wire.
        var requestedFamily = request.GetAttribute<StunRequestedAddressFamilyAttribute>()?.AddressFamily;
        LastAllocateRequestedFamily = requestedFamily;

        if (RefuseAllocationsWith > 0)
        {
            Send(StunMessage.CreateErrorResponse(request, RefuseAllocationsWith, "Refused"), from, key, useSha256);
            return;
        }

        if (request.GetAttribute<StunRequestedTransportAttribute>() is not { Protocol: TurnTransportProtocol.Udp })
        {
            Send(
                StunMessage.CreateErrorResponse(request, StunErrorCodeAttribute.UnsupportedTransportProtocol, "Unsupported Transport Protocol"),
                from,
                key,
                useSha256);
            return;
        }

        IPEndPoint relayed;
        lock (_lock)
        {
            if (_relay is not null && _client is not null && !_client.Equals(from))
            {
                Send(StunMessage.CreateErrorResponse(request, StunErrorCodeAttribute.AllocationMismatch, "Allocation Mismatch"), from, key, useSha256);
                return;
            }

            if (_relay is null)
            {
                var relayFamily = IgnoreRequestedAddressFamily ? AddressFamily.InterNetwork : requestedFamily ?? AddressFamily.InterNetwork;
                var relayAddress = relayFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
                var relay = new Socket(relayFamily, SocketType.Dgram, ProtocolType.Udp);
                relay.Bind(new IPEndPoint(relayAddress, 0));
                _relay = relay;
                _loops.Add(Task.Run(() => RelayLoopAsync(relay, _cts.Token)));
            }

            _client = from;
            relayed = (IPEndPoint)_relay.LocalEndPoint!;
        }

        var response = StunMessage.CreateSuccessResponse(request)
            .Add(new StunXorRelayedAddressAttribute(relayed))
            .Add(new StunXorMappedAddressAttribute(from))
            .Add(new StunLifetimeAttribute(GrantedLifetime));
        Send(response, from, key, useSha256);
    }

    private void HandleRefresh(StunMessage request, IPEndPoint from, byte[] key, bool useSha256)
    {
        var requested = request.GetAttribute<StunLifetimeAttribute>()?.Seconds ?? (uint)GrantedLifetime.TotalSeconds;
        if (requested == 0)
        {
            Interlocked.Increment(ref Releases);
            lock (_lock)
            {
                _relay?.Close();
                _relay = null;
                _permissions.Clear();
                _channels.Clear();
                _channelsByPeer.Clear();
            }

            Send(StunMessage.CreateSuccessResponse(request).Add(new StunLifetimeAttribute(0u)), from, key, useSha256);
            return;
        }

        Interlocked.Increment(ref RefreshRequests);
        Send(StunMessage.CreateSuccessResponse(request).Add(new StunLifetimeAttribute(GrantedLifetime)), from, key, useSha256);
    }

    private void HandleCreatePermission(StunMessage request, IPEndPoint from, byte[] key, bool useSha256)
    {
        Interlocked.Increment(ref CreatePermissionRequests);
        var expiry = DateTimeOffset.UtcNow.AddSeconds(StunLifetimeAttribute.PermissionSeconds);
        lock (_lock)
        {
            foreach (var attribute in request.Attributes)
            {
                if (attribute is StunXorPeerAddressAttribute peer)
                {
                    _permissions[peer.EndPoint.Address] = expiry;
                }
            }
        }

        Send(StunMessage.CreateSuccessResponse(request), from, key, useSha256);
    }

    private void HandleChannelBind(StunMessage request, IPEndPoint from, byte[] key, bool useSha256)
    {
        Interlocked.Increment(ref ChannelBindRequests);
        var channel = request.GetAttribute<StunChannelNumberAttribute>();
        var peer = request.GetAttribute<StunXorPeerAddressAttribute>()?.EndPoint;
        if (channel is null || peer is null)
        {
            Send(StunMessage.CreateErrorResponse(request, StunErrorCodeAttribute.BadRequest, "Bad Request"), from, key, useSha256);
            return;
        }

        lock (_lock)
        {
            _channels[channel.ChannelNumber] = peer;
            _channelsByPeer[peer] = channel.ChannelNumber;

            // RFC 8656 section 11.2: a channel binding also installs a permission.
            _permissions[peer.Address] = DateTimeOffset.UtcNow.AddSeconds(StunLifetimeAttribute.PermissionSeconds);
        }

        Send(StunMessage.CreateSuccessResponse(request), from, key, useSha256);
    }

    private void RelayToPeerByChannel(ushort channelNumber, ReadOnlySpan<byte> payload)
    {
        IPEndPoint? peer;
        lock (_lock)
        {
            _channels.TryGetValue(channelNumber, out peer);
        }

        if (peer is not null)
        {
            RelayToPeer(peer, payload);
        }
    }

    private void RelayToPeer(IPEndPoint peer, ReadOnlySpan<byte> payload)
    {
        Socket? relay;
        lock (_lock)
        {
            relay = _relay;
            if (EnforcePermissions && !_permissions.ContainsKey(peer.Address))
            {
                Interlocked.Increment(ref DroppedUnpermitted);
                return;
            }
        }

        if (relay is null)
        {
            return;
        }

        try
        {
            relay.SendTo(payload, SocketFlags.None, peer);
            Interlocked.Increment(ref RelayedToPeer);
        }
        catch (SocketException)
        {
            // The peer socket went away; nothing to do.
        }
    }

    private async Task RelayLoopAsync(Socket relay, CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        var outbound = new byte[4096 + TurnChannelData.HeaderLength];

        // ReceiveFromAsync's remote-endpoint hint must share the socket's address family, so an
        // IPv6 relay - RFC 8656 section 6.1 via REQUESTED-ADDRESS-FAMILY - needs IPv6Any here.
        EndPoint any = relay.AddressFamily == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : new IPEndPoint(IPAddress.Any, 0);
        while (!cancellationToken.IsCancellationRequested)
        {
            SocketReceiveFromResult result;
            try
            {
                result = await relay.ReceiveFromAsync(buffer, SocketFlags.None, any, cancellationToken);
            }
            catch (Exception)
            {
                return;
            }

            var peer = (IPEndPoint)result.RemoteEndPoint;
            var payload = buffer.AsSpan(0, result.ReceivedBytes);

            Socket? control;
            IPEndPoint? client;
            ushort? channel = null;
            lock (_lock)
            {
                control = _control;
                client = _client;
                if (EnforcePermissions && !_permissions.ContainsKey(peer.Address))
                {
                    Interlocked.Increment(ref DroppedUnpermitted);
                    continue;
                }

                if (_channelsByPeer.TryGetValue(peer, out var bound))
                {
                    channel = bound;
                }
            }

            if (control is null || client is null)
            {
                continue;
            }

            int length;
            if (channel is { } number)
            {
                length = TurnChannelData.Encode(outbound, number, payload);
                Interlocked.Increment(ref ChannelDataToClient);
            }
            else
            {
                var indication = new StunMessage(StunClass.Indication, StunMethod.Data)
                    .Add(new StunXorPeerAddressAttribute(peer))
                    .Add(new StunDataAttribute(payload));
                length = indication.EncodeTo(outbound);
            }

            try
            {
                control.SendTo(outbound.AsSpan(0, length), SocketFlags.None, client);
                Interlocked.Increment(ref RelayedToClient);
            }
            catch (Exception)
            {
                // The control socket is closing.
            }
        }
    }

    private void SendChallenge(StunMessage request, IPEndPoint from, int code, string reason)
    {
        string nonce;
        lock (_lock)
        {
            if (AdvertisePasswordAlgorithms && !_nonce.StartsWith("obMatJos2", StringComparison.Ordinal))
            {
                _nonce = NewNonceValue();
            }

            nonce = _nonce;
        }

        var response = StunMessage.CreateErrorResponse(request, code, reason)
            .Add(new StunRealmAttribute(Realm))
            .Add(new StunNonceAttribute(nonce));

        if (AdvertisePasswordAlgorithms && OfferedPasswordAlgorithms.Count > 0)
        {
            // RFC 8489 section 9.2.4: a challenge whose nonce advertises the password-algorithms
            // feature must carry PASSWORD-ALGORITHMS so the client has something to negotiate with.
            // An empty OfferedPasswordAlgorithms models a misbehaving server that sets the nonce
            // cookie's feature bit but never actually attaches the attribute.
            response.Add(new StunPasswordAlgorithmsAttribute(
                OfferedPasswordAlgorithms.Select(a => new StunPasswordAlgorithmEntry(a))));
        }

        Send(response, from, key: null);
    }

    private void Send(StunMessage message, IPEndPoint to, byte[]? key, bool useSha256 = false)
    {
        try
        {
            _control.SendTo(message.Encode(key, appendFingerprint: true, useMessageIntegritySha256: useSha256), SocketFlags.None, to);
        }
        catch (Exception)
        {
            // The server is shutting down.
        }
    }
}
