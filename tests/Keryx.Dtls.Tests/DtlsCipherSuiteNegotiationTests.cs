using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Keryx.Core;
using Xunit;

namespace Keryx.Dtls.Tests;

/// <summary>
/// Loopback coverage for the broadened cipher-suite and curve support: each new AEAD suite completes a
/// handshake with the certificate type it authenticates, each supported curve completes a handshake,
/// and negotiation selects the strongest mutually supported suite. Built on the same in-memory
/// datagram pair as <see cref="DtlsHandshakeLoopbackTests"/>.
/// </summary>
public class DtlsCipherSuiteNegotiationTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(30);

    public static TheoryData<ushort> EcdsaSuites =>
    [
        CipherSuites.TlsEcdheEcdsaWithAes128GcmSha256,
        CipherSuites.TlsEcdheEcdsaWithAes256GcmSha384,
        CipherSuites.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
    ];

    public static TheoryData<ushort> RsaSuites =>
    [
        CipherSuites.TlsEcdheRsaWithAes128GcmSha256,
        CipherSuites.TlsEcdheRsaWithAes256GcmSha384,
        CipherSuites.TlsEcdheRsaWithChaCha20Poly1305Sha256,
    ];

    public static TheoryData<ushort> Curves =>
    [
        NamedGroups.Secp256r1,
        NamedGroups.Secp384r1,
    ];

    [Theory]
    [MemberData(nameof(EcdsaSuites))]
    public async Task Each_ecdsa_suite_completes_a_loopback_handshake(ushort suite)
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");

        await using var pair = await Harness.ConnectAsync(
            serverCertificate, clientCertificate, suites: [suite]);

        var expected = CipherSuites.Name(suite);
        pair.Client.NegotiatedCipherSuite.Should().Be(expected);
        pair.Server.NegotiatedCipherSuite.Should().Be(expected);
        await pair.RoundTripsAsync();
    }

    [Theory]
    [MemberData(nameof(RsaSuites))]
    public async Task Each_rsa_suite_completes_a_loopback_handshake(ushort suite)
    {
        using var serverCertificate = GenerateRsaCertificate("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");

        await using var pair = await Harness.ConnectAsync(
            serverCertificate, clientCertificate, suites: [suite]);

        var expected = CipherSuites.Name(suite);
        pair.Client.NegotiatedCipherSuite.Should().Be(expected);
        pair.Server.NegotiatedCipherSuite.Should().Be(expected);
        await pair.RoundTripsAsync();
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public async Task Each_curve_completes_a_loopback_handshake(ushort group)
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");

        await using var pair = await Harness.ConnectAsync(
            serverCertificate, clientCertificate, groups: [group]);

        pair.Client.NegotiatedNamedGroup.Should().Be(group);
        pair.Server.NegotiatedNamedGroup.Should().Be(group);

        // The RFC 5705 exporter agrees across the curve just as across the suite.
        pair.Client.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", 60)
            .Should().Equal(pair.Server.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", 60));
        await pair.RoundTripsAsync();
    }

    [Fact]
    public async Task The_existing_aes128_gcm_suite_still_interoperates()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");

        await using var pair = await Harness.ConnectAsync(
            serverCertificate,
            clientCertificate,
            suites: [CipherSuites.TlsEcdheEcdsaWithAes128GcmSha256],
            groups: [NamedGroups.Secp256r1]);

        pair.Client.NegotiatedCipherSuite.Should().Be("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        pair.Client.NegotiatedNamedGroup.Should().Be(NamedGroups.Secp256r1);
        await pair.RoundTripsAsync();
    }

    [Fact]
    public async Task Negotiation_picks_the_server_preferred_suite_from_the_overlap()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");

        // The client offers three suites; the server prefers ChaCha20 first from the overlap.
        await using var pair = await Harness.ConnectAsync(
            serverCertificate,
            clientCertificate,
            serverSuites:
            [
                CipherSuites.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
                CipherSuites.TlsEcdheEcdsaWithAes128GcmSha256,
            ],
            clientSuites:
            [
                CipherSuites.TlsEcdheEcdsaWithAes128GcmSha256,
                CipherSuites.TlsEcdheEcdsaWithAes256GcmSha384,
                CipherSuites.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
            ]);

        pair.Server.NegotiatedCipherSuite.Should().Be("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
        pair.Client.NegotiatedCipherSuite.Should().Be("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
    }

    [Fact]
    public async Task Negotiation_falls_back_to_the_only_shared_suite()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");

        // The only overlap is AES-128-GCM, even though the server prefers AES-256-GCM.
        await using var pair = await Harness.ConnectAsync(
            serverCertificate,
            clientCertificate,
            serverSuites:
            [
                CipherSuites.TlsEcdheEcdsaWithAes256GcmSha384,
                CipherSuites.TlsEcdheEcdsaWithAes128GcmSha256,
            ],
            clientSuites: [CipherSuites.TlsEcdheEcdsaWithAes128GcmSha256]);

        pair.Server.NegotiatedCipherSuite.Should().Be("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    }

    [Fact]
    public async Task Negotiation_picks_the_server_preferred_curve_from_the_overlap()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");

        // Both offer both curves; the server prefers P-384.
        await using var pair = await Harness.ConnectAsync(
            serverCertificate,
            clientCertificate,
            serverGroups: [NamedGroups.Secp384r1, NamedGroups.Secp256r1],
            clientGroups: [NamedGroups.Secp256r1, NamedGroups.Secp384r1]);

        pair.Server.NegotiatedNamedGroup.Should().Be(NamedGroups.Secp384r1);
        pair.Client.NegotiatedNamedGroup.Should().Be(NamedGroups.Secp384r1);
    }

    [Fact]
    public async Task A_client_offering_no_overlapping_curve_fails_the_handshake()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");

        var failure = await Record.ExceptionAsync(async () => await Harness.ConnectAsync(
            serverCertificate,
            clientCertificate,
            serverGroups: [NamedGroups.Secp384r1],
            clientGroups: [NamedGroups.Secp256r1]));

        failure.Should().BeOfType<DtlsException>();
    }

    private static DtlsCertificate GenerateRsaCertificate(string commonName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-15);
        var certificate = request.CreateSelfSigned(notBefore, notBefore.AddDays(1));
        return DtlsCertificate.FromCertificate(certificate);
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly LoopbackDatagramTransport _serverLower;
        private readonly LoopbackDatagramTransport _clientLower;

        private Harness(
            LoopbackDatagramTransport serverLower,
            LoopbackDatagramTransport clientLower,
            DtlsTransport server,
            DtlsTransport client)
        {
            _serverLower = serverLower;
            _clientLower = clientLower;
            Server = server;
            Client = client;
        }

        public DtlsTransport Server { get; }

        public DtlsTransport Client { get; }

        public static async Task<Harness> ConnectAsync(
            DtlsCertificate serverCertificate,
            DtlsCertificate clientCertificate,
            IReadOnlyList<ushort>? suites = null,
            IReadOnlyList<ushort>? groups = null,
            IReadOnlyList<ushort>? serverSuites = null,
            IReadOnlyList<ushort>? clientSuites = null,
            IReadOnlyList<ushort>? serverGroups = null,
            IReadOnlyList<ushort>? clientGroups = null)
        {
            var (serverLower, clientLower) = LoopbackDatagramTransport.CreatePair();

            var server = new DtlsTransport(serverLower, new DtlsConfig
            {
                Role = DtlsRole.Server,
                Certificate = serverCertificate,
                ExpectedRemoteFingerprintSha256 = clientCertificate.Sha256Fingerprint,
                HandshakeTimeout = Patience,
                InitialRetransmitTimeout = TimeSpan.FromMilliseconds(300),
                OfferedCipherSuites = serverSuites ?? suites,
                OfferedNamedGroups = serverGroups ?? groups,
                Logger = NullLogger.Instance,
            });

            var client = new DtlsTransport(clientLower, new DtlsConfig
            {
                Role = DtlsRole.Client,
                Certificate = clientCertificate,
                ExpectedRemoteFingerprintSha256 = serverCertificate.Sha256Fingerprint,
                HandshakeTimeout = Patience,
                InitialRetransmitTimeout = TimeSpan.FromMilliseconds(300),
                OfferedCipherSuites = clientSuites ?? suites,
                OfferedNamedGroups = clientGroups ?? groups,
                Logger = NullLogger.Instance,
            });

            try
            {
                await Task.WhenAll(server.HandshakeAsync(), client.HandshakeAsync()).WaitAsync(Patience);
            }
            catch
            {
                client.Dispose();
                server.Dispose();
                clientLower.Dispose();
                serverLower.Dispose();
                throw;
            }

            return new Harness(serverLower, clientLower, server, client);
        }

        public async Task RoundTripsAsync()
        {
            Client.State.Should().Be(DtlsTransportState.Connected);
            Server.State.Should().Be(DtlsTransportState.Connected);

            using var serverInbox = new Inbox(Server);
            using var clientInbox = new Inbox(Client);

            var toServer = RandomNumberGenerator.GetBytes(200);
            Client.Send(toServer);
            (await serverInbox.TakeAsync()).Should().Equal(toServer);

            var toClient = RandomNumberGenerator.GetBytes(200);
            Server.Send(toClient);
            (await clientInbox.TakeAsync()).Should().Equal(toClient);
        }

        public ValueTask DisposeAsync()
        {
            Client.Dispose();
            Server.Dispose();
            _clientLower.Dispose();
            _serverLower.Dispose();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class Inbox : IDisposable
    {
        private readonly System.Collections.Concurrent.BlockingCollection<byte[]> _items = new();
        private readonly DtlsTransport _transport;
        private readonly DatagramReceivedHandler _handler;

        public Inbox(DtlsTransport transport)
        {
            _transport = transport;
            _handler = datagram => _items.Add(datagram.ToArray());
            transport.OnReceived += _handler;
        }

        public async Task<byte[]> TakeAsync()
        {
            var item = await Task.Run(() => _items.TryTake(out var value, (int)TimeSpan.FromSeconds(10).TotalMilliseconds) ? value : null);
            item.Should().NotBeNull("application data should have been delivered");
            return item!;
        }

        public void Dispose() => _transport.OnReceived -= _handler;
    }
}
