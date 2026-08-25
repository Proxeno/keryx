using System.Collections.Concurrent;
using System.Security.Cryptography;
using FluentAssertions;
using Keryx.Core;
using Xunit;

namespace Keryx.Dtls.Tests;

/// <summary>
/// Server-side HelloVerifyRequest cookie exchange (RFC 6347 §4.2.1). These tests gate
/// <see cref="DtlsConfig.RequireDtlsCookie"/>: the extra round-trip must complete a Keryx↔Keryx
/// handshake, a forged or absent cookie must be re-challenged without allocating handshake state,
/// and the default (cookie-off) flow must be byte-for-byte unchanged.
/// </summary>
public class DtlsCookieTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);

    private static bool IsHandshakeType(byte[] datagram, HandshakeType type) =>
        datagram.Length > DtlsLimits.RecordHeaderLength
        && datagram[0] == (byte)ContentType.Handshake
        && datagram[DtlsLimits.RecordHeaderLength] == (byte)type;

    [Fact]
    public async Task Keryx_client_and_a_cookie_requiring_server_complete_the_full_handshake()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");
        var (serverLower, clientLower) = LoopbackDatagramTransport.CreatePair();

        var sawHelloVerifyRequest = false;
        serverLower.TransformOutbound = (datagram, _) =>
        {
            if (IsHandshakeType(datagram, HandshakeType.HelloVerifyRequest))
            {
                sawHelloVerifyRequest = true;
            }

            return datagram;
        };

        using var server = new DtlsTransport(serverLower, new DtlsConfig
        {
            Role = DtlsRole.Server,
            Certificate = serverCertificate,
            ExpectedRemoteFingerprintSha256 = clientCertificate.Sha256Fingerprint,
            RequireDtlsCookie = true,
            HandshakeTimeout = Patience,
            Logger = NullLogger.Instance,
        });

        using var client = new DtlsTransport(clientLower, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = clientCertificate,
            ExpectedRemoteFingerprintSha256 = serverCertificate.Sha256Fingerprint,
            HandshakeTimeout = Patience,
            Logger = NullLogger.Instance,
        });

        await Task.WhenAll(server.HandshakeAsync(), client.HandshakeAsync()).WaitAsync(Patience);

        server.State.Should().Be(DtlsTransportState.Connected);
        client.State.Should().Be(DtlsTransportState.Connected);
        sawHelloVerifyRequest.Should().BeTrue("the cookie-requiring server must issue a HelloVerifyRequest");

        // The extra round-trip does not change the negotiated session: the exporter still agrees.
        server.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", 60)
            .Should().Equal(client.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", 60));

        clientLower.Dispose();
        serverLower.Dispose();
    }

    [Fact]
    public async Task A_default_server_never_issues_a_HelloVerifyRequest()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");
        var (serverLower, clientLower) = LoopbackDatagramTransport.CreatePair();

        var sawHelloVerifyRequest = false;
        serverLower.TransformOutbound = (datagram, _) =>
        {
            if (IsHandshakeType(datagram, HandshakeType.HelloVerifyRequest))
            {
                sawHelloVerifyRequest = true;
            }

            return datagram;
        };

        using var server = new DtlsTransport(serverLower, new DtlsConfig
        {
            Role = DtlsRole.Server,
            Certificate = serverCertificate,
            ExpectedRemoteFingerprintSha256 = clientCertificate.Sha256Fingerprint,
            HandshakeTimeout = Patience,
            Logger = NullLogger.Instance,
        });

        using var client = new DtlsTransport(clientLower, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = clientCertificate,
            ExpectedRemoteFingerprintSha256 = serverCertificate.Sha256Fingerprint,
            HandshakeTimeout = Patience,
            Logger = NullLogger.Instance,
        });

        await Task.WhenAll(server.HandshakeAsync(), client.HandshakeAsync()).WaitAsync(Patience);

        server.State.Should().Be(DtlsTransportState.Connected);
        client.State.Should().Be(DtlsTransportState.Connected);
        sawHelloVerifyRequest.Should().BeFalse("the WebRTC-default flow must not add a cookie round-trip");

        clientLower.Dispose();
        serverLower.Dispose();
    }

    [Fact]
    public async Task A_forged_cookie_is_re_challenged_and_a_valid_one_lets_the_server_proceed()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        var (serverLower, clientLower) = LoopbackDatagramTransport.CreatePair();

        var outbound = new ConcurrentQueue<byte[]>();
        serverLower.TransformOutbound = (datagram, _) =>
        {
            outbound.Enqueue(datagram);
            return datagram;
        };

        using var server = new DtlsTransport(serverLower, new DtlsConfig
        {
            Role = DtlsRole.Server,
            Certificate = serverCertificate,
            RequireDtlsCookie = true,
            RequirePeerCertificate = false,
            HandshakeTimeout = TimeSpan.FromSeconds(5),
            Logger = NullLogger.Instance,
        });

        _ = server.HandshakeAsync();

        // A first ClientHello (message_seq 0) carrying a bogus cookie the server never issued.
        var random = RandomNumberGenerator.GetBytes(32);
        var forgedCookie = RandomNumberGenerator.GetBytes(20);
        InjectClientHello(clientLower, random, forgedCookie, messageSeq: 0, recordSeq: 0);

        var challenge = await WaitForHandshakeAsync(outbound, HandshakeType.HelloVerifyRequest);
        challenge.Should().NotBeNull("a forged cookie must be re-challenged with a HelloVerifyRequest");

        // No handshake state was created: the server negotiated nothing and holds no peer certificate.
        server.State.Should().Be(DtlsTransportState.Connecting);
        server.NegotiatedCipherSuite.Should().BeNull();
        server.RemoteCertificate.Should().BeNull();
        outbound.Should().NotContain(
            d => IsHandshakeType(d, HandshakeType.ServerHello),
            "a forged cookie must never produce a ServerHello");

        // Echo the cookie the server just issued back in a second ClientHello with the same client
        // parameters: the constant-time check now passes and the server proceeds to its ServerHello.
        var issuedCookie = HandshakeCodec.ParseHelloVerifyRequestCookie(
            challenge!.AsSpan(DtlsLimits.RecordHeaderLength + DtlsLimits.HandshakeHeaderLength));
        InjectClientHello(clientLower, random, issuedCookie, messageSeq: 1, recordSeq: 1);

        var serverHello = await WaitForHandshakeAsync(outbound, HandshakeType.ServerHello);
        serverHello.Should().NotBeNull("a valid cookie must let the server continue past the challenge");

        server.Dispose();
        clientLower.Dispose();
        serverLower.Dispose();
    }

    private static async Task<byte[]?> WaitForHandshakeAsync(
        ConcurrentQueue<byte[]> outbound,
        HandshakeType type)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            foreach (var datagram in outbound)
            {
                if (IsHandshakeType(datagram, type))
                {
                    return datagram;
                }
            }

            await Task.Delay(20);
        }

        return null;
    }

    /// <summary>Crafts a single-record ClientHello and injects it straight to the server.</summary>
    private static void InjectClientHello(
        LoopbackDatagramTransport toServer,
        byte[] random,
        byte[] cookie,
        ushort messageSeq,
        ulong recordSeq)
    {
        var body = HandshakeCodec.BuildClientHello(
            random,
            cookie,
            CipherSuites.PreferenceFor(ecdsaCertificate: true),
            NamedGroups.Preference,
            [SrtpProtectionProfile.Aes128CmHmacSha1Tag80, SrtpProtectionProfile.AeadAes128Gcm]);
        var handshake = HandshakeMessage.Serialize(HandshakeType.ClientHello, messageSeq, body);

        var record = new byte[DtlsLimits.RecordHeaderLength + handshake.Length];
        var writer = new ByteWriter(record);
        writer.WriteU8((byte)ContentType.Handshake);
        writer.WriteU16(ProtocolVersions.Dtls12);
        writer.WriteU16(0); // epoch 0
        writer.WriteU48(recordSeq);
        writer.WriteU16((ushort)handshake.Length);
        writer.WriteBytes(handshake);

        toServer.Send(record);
    }
}
