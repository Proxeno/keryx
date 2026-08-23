using System.Collections.Concurrent;
using System.Security.Cryptography;
using FluentAssertions;
using Keryx.Core;
using Xunit;

namespace Keryx.Dtls.Tests;

/// <summary>
/// End-to-end handshakes between two <see cref="DtlsTransport"/> instances over an in-memory
/// datagram pair. This is the required gate for the layer: it exercises the record layer, the
/// flight state machine, fragmentation, retransmission, mutual authentication, fingerprint pinning
/// and the RFC 5705 exporter together.
/// </summary>
public class DtlsHandshakeLoopbackTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task Full_handshake_completes_with_mutual_fingerprint_pinning()
    {
        await using var fixture = await DtlsPair.ConnectAsync();

        fixture.Client.State.Should().Be(DtlsTransportState.Connected);
        fixture.Server.State.Should().Be(DtlsTransportState.Connected);
        fixture.Client.NegotiatedCipherSuite.Should().Be("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        fixture.Server.NegotiatedCipherSuite.Should().Be("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        fixture.Client.UsedExtendedMasterSecret.Should().BeTrue("Keryx offers RFC 7627 EMS and both sides are Keryx");
        fixture.Server.UsedExtendedMasterSecret.Should().BeTrue();
    }

    [Fact]
    public async Task Each_peer_sees_the_other_certificate_and_fingerprint()
    {
        await using var fixture = await DtlsPair.ConnectAsync();

        fixture.Client.RemoteFingerprint.Should().Be(fixture.ServerCertificate.Sha256Fingerprint);
        fixture.Server.RemoteFingerprint.Should().Be(fixture.ClientCertificate.Sha256Fingerprint);
        fixture.Client.RemoteCertificate.Should().NotBeNull();
        fixture.Client.RemoteCertificate!.RawData.Should().Equal(fixture.ServerCertificate.DerEncoded);
        fixture.Server.RemoteCertificate!.RawData.Should().Equal(fixture.ClientCertificate.DerEncoded);
    }

    [Fact]
    public async Task Application_data_round_trips_in_both_directions()
    {
        await using var fixture = await DtlsPair.ConnectAsync();

        var toServer = "client says hello, this is SCTP-shaped payload"u8.ToArray();
        fixture.Client.Send(toServer);
        (await fixture.ServerInbox.TakeAsync()).Should().Equal(toServer);

        var toClient = RandomNumberGenerator.GetBytes(900);
        fixture.Server.Send(toClient);
        (await fixture.ClientInbox.TakeAsync()).Should().Equal(toClient);

        // And keep going, so sequence numbers advance past the first record in the epoch.
        for (var i = 0; i < 20; i++)
        {
            var payload = RandomNumberGenerator.GetBytes(64);
            fixture.Client.Send(payload);
            (await fixture.ServerInbox.TakeAsync()).Should().Equal(payload);
        }
    }

    [Fact]
    public async Task Exported_keying_material_matches_on_both_sides()
    {
        await using var fixture = await DtlsPair.ConnectAsync();

        fixture.Client.NegotiatedSrtpProfile.Should().Be(SrtpProtectionProfile.Aes128CmHmacSha1Tag80);
        fixture.Server.NegotiatedSrtpProfile.Should().Be(SrtpProtectionProfile.Aes128CmHmacSha1Tag80);

        var length = fixture.Client.NegotiatedSrtpProfile.KeyingMaterialLength();
        length.Should().Be(60);

        var clientKeys = fixture.Client.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", length);
        var serverKeys = fixture.Server.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", length);

        clientKeys.Should().Equal(serverKeys);
        clientKeys.Should().NotEqual(new byte[length]);

        // A different label must produce different material.
        fixture.Client.ExportKeyingMaterial("EXTRACTOR-other", length).Should().NotEqual(clientKeys);
    }

    [Fact]
    public async Task Server_selects_the_first_mutually_supported_srtp_profile()
    {
        await using var fixture = await DtlsPair.ConnectAsync(
            serverProfiles: [SrtpProtectionProfile.AeadAes128Gcm, SrtpProtectionProfile.Aes128CmHmacSha1Tag80],
            clientProfiles: [SrtpProtectionProfile.Aes128CmHmacSha1Tag80, SrtpProtectionProfile.AeadAes128Gcm]);

        fixture.Server.NegotiatedSrtpProfile.Should().Be(SrtpProtectionProfile.AeadAes128Gcm);
        fixture.Client.NegotiatedSrtpProfile.Should().Be(SrtpProtectionProfile.AeadAes128Gcm);
        fixture.Client.NegotiatedSrtpProfile.KeyingMaterialLength().Should().Be(56);
    }

    [Fact]
    public async Task Handshake_survives_the_loss_of_the_first_flight_in_each_direction()
    {
        await using var fixture = await DtlsPair.ConnectAsync(
            dropClientDatagram: static (_, index) => index == 0,
            dropServerDatagram: static (_, index) => index == 0,
            retransmitTimeout: TimeSpan.FromMilliseconds(150));

        fixture.Client.State.Should().Be(DtlsTransportState.Connected);
        fixture.Server.State.Should().Be(DtlsTransportState.Connected);

        var payload = "survived packet loss"u8.ToArray();
        fixture.Client.Send(payload);
        (await fixture.ServerInbox.TakeAsync()).Should().Equal(payload);
    }

    [Fact]
    public async Task Handshake_survives_heavy_uniform_loss()
    {
        // Drop every third datagram in both directions; retransmission must carry the handshake.
        await using var fixture = await DtlsPair.ConnectAsync(
            dropClientDatagram: static (_, index) => index % 3 == 0,
            dropServerDatagram: static (_, index) => index % 3 == 1,
            retransmitTimeout: TimeSpan.FromMilliseconds(120));

        fixture.Client.State.Should().Be(DtlsTransportState.Connected);
        fixture.Server.State.Should().Be(DtlsTransportState.Connected);
        fixture.Client.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", 60)
            .Should().Equal(fixture.Server.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", 60));
    }

    [Fact]
    public async Task Handshake_fragments_and_reassembles_across_a_small_mtu()
    {
        await using var fixture = await DtlsPair.ConnectAsync(mtu: 200);

        fixture.Client.State.Should().Be(DtlsTransportState.Connected);
        fixture.Server.State.Should().Be(DtlsTransportState.Connected);

        // A certificate does not fit in a 200-byte record, so fragmentation must have happened.
        fixture.ServerLower.SentCount.Should().BeGreaterThan(4);

        var payload = RandomNumberGenerator.GetBytes(100);
        fixture.Server.Send(payload);
        (await fixture.ClientInbox.TakeAsync()).Should().Equal(payload);
    }

    [Fact]
    public async Task A_wrong_expected_fingerprint_aborts_the_handshake_on_the_client()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");
        using var impostor = DtlsCertificate.GenerateSelfSigned("impostor");
        var (left, right) = LoopbackDatagramTransport.CreatePair();

        using var server = new DtlsTransport(left, new DtlsConfig
        {
            Role = DtlsRole.Server,
            Certificate = serverCertificate,
            HandshakeTimeout = Patience,
        });

        using var client = new DtlsTransport(right, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = clientCertificate,
            ExpectedRemoteFingerprintSha256 = impostor.Sha256Fingerprint,
            HandshakeTimeout = Patience,
        });

        var serverTask = server.HandshakeAsync();
        var clientTask = client.HandshakeAsync();

        var failure = await Record.ExceptionAsync(async () => await clientTask);
        failure.Should().BeOfType<DtlsException>()
            .Which.Alert.Should().Be(DtlsAlertDescription.BadCertificate);
        client.State.Should().Be(DtlsTransportState.Failed);

        // The client's bad_certificate alert must also tear the server down.
        var serverFailure = await Record.ExceptionAsync(async () => await serverTask);
        serverFailure.Should().BeOfType<DtlsException>();
        server.State.Should().Be(DtlsTransportState.Failed);

        left.Dispose();
        right.Dispose();
    }

    [Fact]
    public async Task A_wrong_expected_fingerprint_aborts_the_handshake_on_the_server()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");
        using var impostor = DtlsCertificate.GenerateSelfSigned("impostor");
        var (left, right) = LoopbackDatagramTransport.CreatePair();

        using var server = new DtlsTransport(left, new DtlsConfig
        {
            Role = DtlsRole.Server,
            Certificate = serverCertificate,
            ExpectedRemoteFingerprintSha256 = impostor.Sha256Fingerprint,
            HandshakeTimeout = Patience,
        });

        using var client = new DtlsTransport(right, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = clientCertificate,
            ExpectedRemoteFingerprintSha256 = serverCertificate.Sha256Fingerprint,
            HandshakeTimeout = Patience,
        });

        var serverTask = server.HandshakeAsync();
        var clientTask = client.HandshakeAsync();

        var failure = await Record.ExceptionAsync(async () => await serverTask);
        failure.Should().BeOfType<DtlsException>()
            .Which.Alert.Should().Be(DtlsAlertDescription.BadCertificate);

        var clientFailure = await Record.ExceptionAsync(async () => await clientTask);
        clientFailure.Should().BeOfType<DtlsException>();

        left.Dispose();
        right.Dispose();
    }

    [Fact]
    public async Task A_tampered_client_Finished_aborts_the_server()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");
        var (left, right) = LoopbackDatagramTransport.CreatePair();

        using var server = new DtlsTransport(left, new DtlsConfig
        {
            Role = DtlsRole.Server,
            Certificate = serverCertificate,
            HandshakeTimeout = TimeSpan.FromSeconds(10),
        });

        using var client = new DtlsTransport(right, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = clientCertificate,
            HandshakeTimeout = TimeSpan.FromSeconds(10),
        })
        {
            TestCorruptOutgoingFinished = true,
        };

        var serverTask = server.HandshakeAsync();
        var clientTask = client.HandshakeAsync();

        var failure = await Record.ExceptionAsync(async () => await serverTask);
        failure.Should().BeOfType<DtlsException>()
            .Which.Alert.Should().Be(DtlsAlertDescription.DecryptError);

        (await Record.ExceptionAsync(async () => await clientTask)).Should().NotBeNull();

        left.Dispose();
        right.Dispose();
    }

    [Fact]
    public async Task A_tampered_client_CertificateVerify_aborts_the_server()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");
        var (left, right) = LoopbackDatagramTransport.CreatePair();

        using var server = new DtlsTransport(left, new DtlsConfig
        {
            Role = DtlsRole.Server,
            Certificate = serverCertificate,
            HandshakeTimeout = TimeSpan.FromSeconds(10),
        });

        using var client = new DtlsTransport(right, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = clientCertificate,
            HandshakeTimeout = TimeSpan.FromSeconds(10),
        })
        {
            TestCorruptOutgoingCertificateVerify = true,
        };

        var serverTask = server.HandshakeAsync();
        var clientTask = client.HandshakeAsync();

        var failure = await Record.ExceptionAsync(async () => await serverTask);
        failure.Should().BeOfType<DtlsException>()
            .Which.Alert.Should().Be(DtlsAlertDescription.DecryptError);

        (await Record.ExceptionAsync(async () => await clientTask)).Should().NotBeNull();

        left.Dispose();
        right.Dispose();
    }

    [Fact]
    public async Task A_tampered_encrypted_record_is_discarded_silently()
    {
        await using var fixture = await DtlsPair.ConnectAsync();

        // Flip a bit in the ciphertext of every application-data record the client sends.
        fixture.ClientLower.TransformOutbound = (datagram, _) =>
        {
            if (datagram.Length > 0 && datagram[0] == (byte)ContentType.ApplicationData)
            {
                datagram[^1] ^= 0x01;
            }

            return datagram;
        };

        fixture.Client.Send("this will be corrupted"u8.ToArray());

        // Nothing surfaces, and the connection stays up (RFC 6347 4.1.2.7 silent discard).
        var delivered = await fixture.ServerInbox.TryTakeAsync(TimeSpan.FromMilliseconds(400));
        delivered.Should().BeNull();
        fixture.Server.State.Should().Be(DtlsTransportState.Connected);

        fixture.ClientLower.TransformOutbound = null;
        var good = "this one is fine"u8.ToArray();
        fixture.Client.Send(good);
        (await fixture.ServerInbox.TakeAsync()).Should().Equal(good);
    }

    [Fact]
    public async Task A_replayed_application_record_is_delivered_only_once()
    {
        await using var fixture = await DtlsPair.ConnectAsync();

        var captured = new List<byte[]>();
        fixture.ClientLower.TransformOutbound = (datagram, _) =>
        {
            if (datagram.Length > 0 && datagram[0] == (byte)ContentType.ApplicationData)
            {
                captured.Add(datagram);
            }

            return datagram;
        };

        var payload = "deliver me exactly once"u8.ToArray();
        fixture.Client.Send(payload);
        (await fixture.ServerInbox.TakeAsync()).Should().Equal(payload);

        captured.Should().HaveCount(1);
        fixture.ClientLower.TransformOutbound = null;

        // Replay the exact same datagram: the anti-replay window must swallow it.
        fixture.ClientLower.Send(captured[0]);
        (await fixture.ServerInbox.TryTakeAsync(TimeSpan.FromMilliseconds(400))).Should().BeNull();
        fixture.Server.State.Should().Be(DtlsTransportState.Connected);
    }

    [Fact]
    public async Task Close_notifies_the_peer_and_moves_both_sides_to_closed()
    {
        await using var fixture = await DtlsPair.ConnectAsync();

        fixture.Client.Close();
        fixture.Client.State.Should().Be(DtlsTransportState.Closed);

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (fixture.Server.State != DtlsTransportState.Closed && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        fixture.Server.State.Should().Be(DtlsTransportState.Closed);
    }

    [Fact]
    public async Task State_changes_are_reported_in_order()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");
        var (left, right) = LoopbackDatagramTransport.CreatePair();

        using var server = new DtlsTransport(left, new DtlsConfig
        {
            Role = DtlsRole.Server,
            Certificate = serverCertificate,
            HandshakeTimeout = Patience,
        });

        using var client = new DtlsTransport(right, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = clientCertificate,
            HandshakeTimeout = Patience,
        });

        var states = new ConcurrentQueue<DtlsTransportState>();
        client.OnStateChanged += (_, state) => states.Enqueue(state);

        await Task.WhenAll(server.HandshakeAsync(), client.HandshakeAsync()).WaitAsync(Patience);

        // OnStateChanged is dispatched from Pump(), which runs independently of the
        // _handshakeCompletion continuation observed above, so the Connected notification can
        // still be in flight when HandshakeAsync returns. Wait for it deterministically instead
        // of sampling the queue immediately.
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (states.Count < 2 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        states.Should().Equal(DtlsTransportState.Connecting, DtlsTransportState.Connected);

        left.Dispose();
        right.Dispose();
    }

    [Fact]
    public async Task Exporting_before_the_handshake_completes_throws()
    {
        using var certificate = DtlsCertificate.GenerateSelfSigned();
        var (left, right) = LoopbackDatagramTransport.CreatePair();
        using var client = new DtlsTransport(right, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = certificate,
        });

        var act = () => client.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", 60);

        act.Should().Throw<InvalidOperationException>();
        client.Invoking(c => c.Send([1, 2, 3])).Should().Throw<InvalidOperationException>();

        left.Dispose();
        right.Dispose();
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Handshake_times_out_when_the_peer_never_answers()
    {
        using var certificate = DtlsCertificate.GenerateSelfSigned();
        var (left, right) = LoopbackDatagramTransport.CreatePair();
        left.DropOutbound = static (_, _) => true;
        right.DropOutbound = static (_, _) => true;

        using var client = new DtlsTransport(right, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = certificate,
            HandshakeTimeout = TimeSpan.FromMilliseconds(400),
            InitialRetransmitTimeout = TimeSpan.FromMilliseconds(100),
        });

        var failure = await Record.ExceptionAsync(async () => await client.HandshakeAsync());

        failure.Should().BeOfType<DtlsException>();
        client.State.Should().Be(DtlsTransportState.Failed);

        left.Dispose();
        right.Dispose();
    }

    [Fact]
    public async Task Server_without_a_client_certificate_requirement_still_pins_when_asked()
    {
        // Sanity: pinning both ways with the correct fingerprints succeeds repeatedly.
        for (var i = 0; i < 3; i++)
        {
            await using var fixture = await DtlsPair.ConnectAsync();
            fixture.Client.State.Should().Be(DtlsTransportState.Connected);
            fixture.Server.State.Should().Be(DtlsTransportState.Connected);
        }
    }

    /// <summary>A connected client/server pair over a loopback datagram pair.</summary>
    private sealed class DtlsPair : IAsyncDisposable
    {
        private DtlsPair(
            DtlsCertificate serverCertificate,
            DtlsCertificate clientCertificate,
            LoopbackDatagramTransport serverLower,
            LoopbackDatagramTransport clientLower,
            DtlsTransport server,
            DtlsTransport client)
        {
            ServerCertificate = serverCertificate;
            ClientCertificate = clientCertificate;
            ServerLower = serverLower;
            ClientLower = clientLower;
            Server = server;
            Client = client;
            ServerInbox = new Inbox(server);
            ClientInbox = new Inbox(client);
        }

        public DtlsCertificate ServerCertificate { get; }

        public DtlsCertificate ClientCertificate { get; }

        public LoopbackDatagramTransport ServerLower { get; }

        public LoopbackDatagramTransport ClientLower { get; }

        public DtlsTransport Server { get; }

        public DtlsTransport Client { get; }

        public Inbox ServerInbox { get; }

        public Inbox ClientInbox { get; }

        public static async Task<DtlsPair> ConnectAsync(
            IReadOnlyList<SrtpProtectionProfile>? serverProfiles = null,
            IReadOnlyList<SrtpProtectionProfile>? clientProfiles = null,
            Func<byte[], int, bool>? dropClientDatagram = null,
            Func<byte[], int, bool>? dropServerDatagram = null,
            TimeSpan? retransmitTimeout = null,
            int mtu = DtlsLimits.DefaultMtu)
        {
            var serverCertificate = DtlsCertificate.GenerateSelfSigned("keryx-server");
            var clientCertificate = DtlsCertificate.GenerateSelfSigned("keryx-client");
            var (serverLower, clientLower) = LoopbackDatagramTransport.CreatePair();
            serverLower.DropOutbound = dropServerDatagram;
            clientLower.DropOutbound = dropClientDatagram;

            var server = new DtlsTransport(serverLower, new DtlsConfig
            {
                Role = DtlsRole.Server,
                Certificate = serverCertificate,
                ExpectedRemoteFingerprintSha256 = clientCertificate.Sha256Fingerprint,
                SrtpProfiles = serverProfiles ?? [SrtpProtectionProfile.Aes128CmHmacSha1Tag80, SrtpProtectionProfile.AeadAes128Gcm],
                HandshakeTimeout = Patience,
                InitialRetransmitTimeout = retransmitTimeout ?? TimeSpan.FromMilliseconds(300),
                MaxDatagramSize = mtu,
                Logger = NullLogger.Instance,
            });

            var client = new DtlsTransport(clientLower, new DtlsConfig
            {
                Role = DtlsRole.Client,
                Certificate = clientCertificate,
                ExpectedRemoteFingerprintSha256 = serverCertificate.Sha256Fingerprint,
                SrtpProfiles = clientProfiles ?? [SrtpProtectionProfile.Aes128CmHmacSha1Tag80, SrtpProtectionProfile.AeadAes128Gcm],
                HandshakeTimeout = Patience,
                InitialRetransmitTimeout = retransmitTimeout ?? TimeSpan.FromMilliseconds(300),
                MaxDatagramSize = mtu,
                Logger = NullLogger.Instance,
            });

            var pair = new DtlsPair(serverCertificate, clientCertificate, serverLower, clientLower, server, client);

            await Task.WhenAll(server.HandshakeAsync(), client.HandshakeAsync()).WaitAsync(Patience);
            return pair;
        }

        public ValueTask DisposeAsync()
        {
            Client.Dispose();
            Server.Dispose();
            ClientLower.Dispose();
            ServerLower.Dispose();
            ClientCertificate.Dispose();
            ServerCertificate.Dispose();
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>Collects application data raised by a <see cref="DtlsTransport"/>.</summary>
    private sealed class Inbox
    {
        private readonly BlockingCollection<byte[]> _items = new();

        public Inbox(DtlsTransport transport)
        {
            transport.OnReceived += datagram => _items.Add(datagram.ToArray());
        }

        public async Task<byte[]> TakeAsync()
        {
            var item = await TryTakeAsync(TimeSpan.FromSeconds(10));
            item.Should().NotBeNull("application data should have been delivered");
            return item!;
        }

        public Task<byte[]?> TryTakeAsync(TimeSpan timeout) => Task.Run(() =>
            _items.TryTake(out var item, (int)timeout.TotalMilliseconds) ? item : null);
    }
}
