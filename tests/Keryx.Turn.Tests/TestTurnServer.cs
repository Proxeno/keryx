using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Keryx.Stun;
using Keryx.Turn;

namespace Keryx.Turn.Tests;

/// <summary>
/// A deliberately small but genuine TURN server (RFC 8656) over loopback: long-term authentication
/// with a 401 challenge, one allocation on a real second socket, permissions, channel bindings,
/// ChannelData and Send/Data indications. The client-to-server leg is UDP by default, or TCP / TLS
/// (RFC 5766 section 2.1) when constructed with that transport - the peer-facing relay is always UDP.
/// </summary>
/// <remarks>
/// It exists so the relay can be *observed*: every relayed datagram is counted, the relayed
/// address is a socket the server really owns and really sends from, and permissions are enforced,
/// so a test can prove a packet went through the allocation rather than taking a host shortcut.
/// </remarks>
internal sealed class TestTurnServer : IDisposable
{
    private readonly TurnClientTransport _transport;
    private readonly Socket? _control;
    private readonly Socket? _listener;
    private readonly X509Certificate2? _certificate;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _lock = new();
    private readonly object _streamWriteLock = new();
    private readonly Dictionary<IPAddress, DateTimeOffset> _permissions = [];
    private readonly Dictionary<ushort, IPEndPoint> _channels = [];
    private readonly Dictionary<IPEndPoint, ushort> _channelsByPeer = [];
    private readonly List<Task> _loops = [];

    private Socket? _relay;
    private IPEndPoint? _client;
    private Stream? _clientStream;
    private string _nonce = NewNonce();
    private int _noncesIssued;
    private bool _disposed;

    public TestTurnServer(
        string username = "keryx",
        string password = "keryxpass",
        string realm = "keryx.test",
        TurnClientTransport transport = TurnClientTransport.Udp)
    {
        Username = username;
        Password = password;
        Realm = realm;
        _transport = transport;

        if (transport == TurnClientTransport.Udp)
        {
            _control = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _control.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            EndPoint = (IPEndPoint)_control.LocalEndPoint!;
            lock (_lock)
            {
                _loops.Add(Task.Run(() => ControlLoopAsync(_cts.Token)));
            }
        }
        else
        {
            _certificate = transport == TurnClientTransport.Tls ? CreateSelfSignedCertificate(realm) : null;
            _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _listener.Listen(1);
            EndPoint = (IPEndPoint)_listener.LocalEndPoint!;
            lock (_lock)
            {
                _loops.Add(Task.Run(() => AcceptLoopAsync(_cts.Token)));
            }
        }
    }

    /// <summary>The self-signed certificate a TLS server presents, so a test can pin it in validation.</summary>
    public X509Certificate2? Certificate => _certificate;

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

    public TurnServerOptions ToOptions() => new(EndPoint, Username, Password) { ClientTransport = _transport };

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cts.Cancel();
        _control?.Close();
        _listener?.Close();
        Task[] loops;
        Stream? clientStream;
        lock (_lock)
        {
            _relay?.Close();
            clientStream = _clientStream;
            loops = [.. _loops];
        }

        try
        {
            clientStream?.Dispose();
        }
        catch (Exception)
        {
            // The stream is being torn down.
        }

        try
        {
            Task.WhenAll(loops).Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // The loops only ever fault because their socket was closed above.
        }

        _control?.Dispose();
        _listener?.Dispose();
        _relay?.Dispose();
        _certificate?.Dispose();
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
                result = await _control!.ReceiveFromAsync(buffer, SocketFlags.None, any, cancellationToken);
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

            IPEndPoint? client;
            ushort? channel = null;
            lock (_lock)
            {
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

            if (client is null)
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

            if (DeliverToClient(outbound.AsSpan(0, length), client))
            {
                Interlocked.Increment(ref RelayedToClient);
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
        var encoded = message.Encode(key, appendFingerprint: true, useMessageIntegritySha256: useSha256);
        DeliverToClient(encoded, to);
    }

    /// <summary>
    /// Writes one framed STUN or ChannelData message to the client over whichever transport is in
    /// use: a UDP datagram, or a stream write padded to a four-byte boundary (RFC 5766 section 11.5).
    /// </summary>
    private bool DeliverToClient(ReadOnlySpan<byte> framed, IPEndPoint to)
    {
        if (_transport == TurnClientTransport.Udp)
        {
            try
            {
                _control!.SendTo(framed, SocketFlags.None, to);
                return true;
            }
            catch (Exception)
            {
                // The server is shutting down.
                return false;
            }
        }

        Stream? stream;
        lock (_lock)
        {
            stream = _clientStream;
        }

        if (stream is null)
        {
            return false;
        }

        var padded = (framed.Length + 3) & ~3;
        try
        {
            lock (_streamWriteLock)
            {
                stream.Write(framed);
                if (padded > framed.Length)
                {
                    Span<byte> pad = stackalloc byte[4];
                    pad.Clear();
                    stream.Write(pad[..(padded - framed.Length)]);
                }

                stream.Flush();
            }

            return true;
        }
        catch (Exception)
        {
            // The connection is closing.
            return false;
        }
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        Socket accepted;
        try
        {
            accepted = await _listener!.AcceptAsync(cancellationToken);
        }
        catch (Exception)
        {
            return;
        }

        accepted.NoDelay = true;
        Stream stream = new NetworkStream(accepted, ownsSocket: true);
        try
        {
            if (_transport == TurnClientTransport.Tls)
            {
                var tls = new SslStream(stream, leaveInnerStreamOpen: false);
                await tls.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _certificate,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    },
                    cancellationToken);
                stream = tls;
            }
        }
        catch (Exception)
        {
            stream.Dispose();
            return;
        }

        var client = (IPEndPoint)accepted.RemoteEndPoint!;
        lock (_lock)
        {
            _clientStream = stream;
            _client = client;
        }

        await StreamReadLoopAsync(stream, client, cancellationToken);
    }

    private async Task StreamReadLoopAsync(Stream stream, IPEndPoint client, CancellationToken cancellationToken)
    {
        var reassembler = new TurnStreamReassembler();
        var buffer = new byte[8192];
        while (!cancellationToken.IsCancellationRequested)
        {
            int read;
            try
            {
                read = await stream.ReadAsync(buffer, cancellationToken);
            }
            catch (Exception)
            {
                return;
            }

            if (read == 0)
            {
                return;
            }

            reassembler.Append(buffer.AsSpan(0, read));
            while (true)
            {
                ReadOnlySpan<byte> message;
                try
                {
                    if (!reassembler.TryReadMessage(out message))
                    {
                        break;
                    }
                }
                catch (Exception)
                {
                    return;
                }

                if (TurnChannelData.TryDecode(message, out var channelNumber, out var payload))
                {
                    Interlocked.Increment(ref ChannelDataFromClient);
                    RelayToPeerByChannel(channelNumber, payload);
                    continue;
                }

                if (StunMessage.TryDecode(message, out var stun))
                {
                    HandleMessage(stun, message.ToArray(), client);
                }
            }
        }
    }

    private static X509Certificate2 CreateSelfSignedCertificate(string commonName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var subjectAlternativeName = new SubjectAlternativeNameBuilder();
        subjectAlternativeName.AddDnsName(commonName);
        subjectAlternativeName.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(subjectAlternativeName.Build());

        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Re-import through a PFX so the private key is usable for SslStream server authentication
        // across platforms, where the ephemeral key from CreateSelfSigned is not always accepted.
        var exported = certificate.Export(X509ContentType.Pfx);
        certificate.Dispose();
        return X509CertificateLoader.LoadPkcs12(exported, password: null);
    }
}
