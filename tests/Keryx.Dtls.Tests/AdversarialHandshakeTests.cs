using FluentAssertions;
using Keryx.Core;
using Xunit;

namespace Keryx.Dtls.Tests;

/// <summary>
/// Attacker-driven handshake tests. Every test here injects or rewrites bytes on the wire the way a
/// hostile peer or an off-path injector would, and asserts that Keryx fails <em>closed</em>.
/// </summary>
public class AdversarialHandshakeTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);

    /// <summary>
    /// RFC 5246 §7.4.1.2 / RFC 6347 §4.2.1: a server that does not support the client's offered
    /// <c>client_version</c> MUST abort with <c>protocol_version</c>. Keryx implements DTLS 1.2
    /// only, so a ClientHello claiming DTLS 1.0 must be refused rather than silently answered with
    /// a DTLS 1.2 ServerHello.
    /// </summary>
    [Fact]
    public async Task A_ClientHello_offering_DTLS_1_0_is_refused_with_protocol_version()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");
        var (serverLower, clientLower) = LoopbackDatagramTransport.CreatePair();

        // Rewrite ClientHello.client_version from DTLS 1.2 (0xFEFD) to DTLS 1.0 (0xFEFF).
        // Layout: 13-byte record header, 12-byte handshake header, then client_version.
        clientLower.TransformOutbound = (datagram, _) =>
        {
            const int VersionOffset = DtlsLimits.RecordHeaderLength + DtlsLimits.HandshakeHeaderLength;
            if (datagram.Length > VersionOffset + 1
                && datagram[0] == (byte)ContentType.Handshake
                && datagram[DtlsLimits.RecordHeaderLength] == (byte)HandshakeType.ClientHello)
            {
                datagram[VersionOffset] = 0xFE;
                datagram[VersionOffset + 1] = 0xFF;
            }

            return datagram;
        };

        using var server = new DtlsTransport(serverLower, new DtlsConfig
        {
            Role = DtlsRole.Server,
            Certificate = serverCertificate,
            HandshakeTimeout = TimeSpan.FromSeconds(5),
            Logger = NullLogger.Instance,
        });

        using var client = new DtlsTransport(clientLower, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = clientCertificate,
            HandshakeTimeout = TimeSpan.FromSeconds(5),
            Logger = NullLogger.Instance,
        });

        var serverTask = server.HandshakeAsync();
        _ = client.HandshakeAsync();

        var failure = await Record.ExceptionAsync(async () => await serverTask);
        failure.Should().BeOfType<DtlsException>()
            .Which.Alert.Should().Be(DtlsAlertDescription.ProtocolVersion);

        clientLower.Dispose();
        serverLower.Dispose();
    }

    /// <summary>
    /// An off-path injector replays the client's ClientHello with a fresh <c>message_seq</c> while
    /// the handshake is in flight. RFC 6347 §4.2.4: a server in the middle of a handshake must not
    /// treat that as a new handshake. If it does, the injector both destroys the legitimate
    /// session's state and gets a multi-kilobyte certificate flight emitted for one small datagram.
    /// </summary>
    [Fact]
    public async Task An_injected_second_ClientHello_does_not_restart_the_server_handshake()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");
        var (serverLower, clientLower) = LoopbackDatagramTransport.CreatePair();

        byte[]? capturedHello = null;
        clientLower.TransformOutbound = (datagram, _) =>
        {
            if (capturedHello is null
                && datagram.Length > DtlsLimits.RecordHeaderLength
                && datagram[0] == (byte)ContentType.Handshake
                && datagram[DtlsLimits.RecordHeaderLength] == (byte)HandshakeType.ClientHello)
            {
                capturedHello = (byte[])datagram.Clone();
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

        var serverTask = server.HandshakeAsync();
        var clientTask = client.HandshakeAsync();
        await Task.WhenAll(serverTask, clientTask).WaitAsync(Patience);

        capturedHello.Should().NotBeNull("the ClientHello must have been observed on the wire");

        // Re-inject the ClientHello with message_seq 1 and a fresh record sequence number, so it is
        // neither a record-layer replay nor a handshake retransmission of message_seq 0.
        var injected = (byte[])capturedHello!.Clone();
        injected[DtlsLimits.RecordHeaderLength - 1 - 6] = 0; // epoch high byte, kept at 0
        injected[10] = 9;                                   // record sequence_number low byte
        injected[DtlsLimits.RecordHeaderLength + 4] = 0;     // message_seq high byte
        injected[DtlsLimits.RecordHeaderLength + 5] = 1;     // message_seq low byte

        var flightsBefore = serverLower.SentCount;
        clientLower.Send(injected);
        await Task.Delay(300);

        // The server must not have restarted: no new flight, and the session is untouched.
        serverLower.SentCount.Should().Be(
            flightsBefore,
            "an injected ClientHello must not make an established server emit a new handshake flight");
        server.State.Should().Be(DtlsTransportState.Connected);

        clientLower.Dispose();
        serverLower.Dispose();
    }

    /// <summary>
    /// The same injection, but landing while the server is still mid-handshake — the window in
    /// which the state machine is most willing to accept a ClientHello.
    /// </summary>
    [Fact]
    public async Task An_injected_ClientHello_mid_handshake_is_rejected_as_unexpected()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");
        var (serverLower, clientLower) = LoopbackDatagramTransport.CreatePair();

        byte[]? capturedHello = null;

        // Hold back everything the client sends after the ClientHello, so the server stays parked
        // in the middle of the handshake while the injection lands.
        clientLower.TransformOutbound = (datagram, _) =>
        {
            var isHello = datagram.Length > DtlsLimits.RecordHeaderLength
                          && datagram[0] == (byte)ContentType.Handshake
                          && datagram[DtlsLimits.RecordHeaderLength] == (byte)HandshakeType.ClientHello;
            if (isHello)
            {
                capturedHello ??= (byte[])datagram.Clone();
                return datagram;
            }

            return null;
        };

        using var server = new DtlsTransport(serverLower, new DtlsConfig
        {
            Role = DtlsRole.Server,
            Certificate = serverCertificate,
            ExpectedRemoteFingerprintSha256 = clientCertificate.Sha256Fingerprint,
            HandshakeTimeout = TimeSpan.FromSeconds(5),
            Logger = NullLogger.Instance,
        });

        using var client = new DtlsTransport(clientLower, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = clientCertificate,
            ExpectedRemoteFingerprintSha256 = serverCertificate.Sha256Fingerprint,
            HandshakeTimeout = TimeSpan.FromSeconds(5),
            Logger = NullLogger.Instance,
        });

        var serverTask = server.HandshakeAsync();
        _ = client.HandshakeAsync();

        // Wait for the server to answer the ClientHello with its flight.
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(3);
        while (serverLower.SentCount == 0 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        capturedHello.Should().NotBeNull();

        var injected = (byte[])capturedHello!.Clone();
        injected[10] = 9;                                // record sequence_number low byte
        injected[DtlsLimits.RecordHeaderLength + 4] = 0;  // message_seq high byte
        injected[DtlsLimits.RecordHeaderLength + 5] = 1;  // message_seq low byte

        var flightsBefore = serverLower.SentCount;
        clientLower.Send(injected);

        var failure = await Record.ExceptionAsync(async () => await serverTask);
        failure.Should().BeOfType<DtlsException>()
            .Which.Alert.Should().Be(DtlsAlertDescription.UnexpectedMessage);

        // And it must not have been answered with a second certificate flight: a 113-byte injected
        // ClientHello reflecting a ~1 kB server flight is roughly 10x amplification.
        serverLower.SentCount.Should().BeLessThanOrEqualTo(
            flightsBefore + 1,
            "the only datagram the server may emit in response is the fatal alert");
        failure.Should().BeOfType<DtlsException>()
            .Which.Alert.Should().Be(DtlsAlertDescription.UnexpectedMessage);

        clientLower.Dispose();
        serverLower.Dispose();
    }

    /// <summary>
    /// RFC 6347 §4.1.2.6: "the window and window bits MUST NOT be updated until the packet is
    /// authenticated". At epoch 0 nothing can be authenticated, so running the anti-replay window
    /// there lets one forged record with a maximal sequence number anchor the window at 2^48-1 and
    /// drop every genuine record that follows. Thirteen bytes, no body, and the handshake never
    /// completes.
    /// </summary>
    [Fact]
    public async Task A_forged_epoch_zero_record_cannot_wedge_the_replay_window()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");
        var (serverLower, clientLower) = LoopbackDatagramTransport.CreatePair();

        using var server = new DtlsTransport(serverLower, new DtlsConfig
        {
            Role = DtlsRole.Server,
            Certificate = serverCertificate,
            ExpectedRemoteFingerprintSha256 = clientCertificate.Sha256Fingerprint,
            HandshakeTimeout = TimeSpan.FromSeconds(8),
            Logger = NullLogger.Instance,
        });

        using var client = new DtlsTransport(clientLower, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = clientCertificate,
            ExpectedRemoteFingerprintSha256 = serverCertificate.Sha256Fingerprint,
            HandshakeTimeout = TimeSpan.FromSeconds(8),
            Logger = NullLogger.Instance,
        });

        var serverTask = server.HandshakeAsync();

        // handshake / DTLS 1.2 / epoch 0 / sequence_number 2^48-1 / zero-length body.
        byte[] poison = [0x16, 0xFE, 0xFD, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00];
        clientLower.Send(poison);
        await Task.Delay(50);

        var clientTask = client.HandshakeAsync();

        await Task.WhenAll(serverTask, clientTask).WaitAsync(TimeSpan.FromSeconds(15));
        server.State.Should().Be(DtlsTransportState.Connected);
        client.State.Should().Be(DtlsTransportState.Connected);

        clientLower.Dispose();
        serverLower.Dispose();
    }

    /// <summary>
    /// RFC 6347 §4.1.2.7 requires invalid records to be discarded. Filling the reassembler's
    /// out-of-order slots with zero-length fragments for message_seq values that will never be
    /// reached must not be able to abort the connection — a local buffering limit is not a protocol
    /// error, and here it is reachable from wholly unauthenticated input.
    /// </summary>
    [Fact]
    public async Task Filling_the_reassembly_slots_cannot_abort_the_handshake()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");
        var (serverLower, clientLower) = LoopbackDatagramTransport.CreatePair();

        using var server = new DtlsTransport(serverLower, new DtlsConfig
        {
            Role = DtlsRole.Server,
            Certificate = serverCertificate,
            ExpectedRemoteFingerprintSha256 = clientCertificate.Sha256Fingerprint,
            HandshakeTimeout = TimeSpan.FromSeconds(8),
            Logger = NullLogger.Instance,
        });

        using var client = new DtlsTransport(clientLower, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = clientCertificate,
            ExpectedRemoteFingerprintSha256 = serverCertificate.Sha256Fingerprint,
            HandshakeTimeout = TimeSpan.FromSeconds(8),
            Logger = NullLogger.Instance,
        });

        var serverTask = server.HandshakeAsync();

        // One record carrying 64 empty fragments, each for a distinct far-future message_seq.
        const int Count = 64;
        var body = new byte[Count * DtlsLimits.HandshakeHeaderLength];
        for (var i = 0; i < Count; i++)
        {
            var at = i * DtlsLimits.HandshakeHeaderLength;
            body[at] = (byte)HandshakeType.Certificate;
            // length = 0, fragment_offset = 0, fragment_length = 0; only message_seq varies.
            body[at + 4] = (byte)((100 + i) >> 8);
            body[at + 5] = (byte)(100 + i);
        }

        var datagram = new byte[DtlsLimits.RecordHeaderLength + body.Length];
        datagram[0] = (byte)ContentType.Handshake;
        datagram[1] = 0xFE;
        datagram[2] = 0xFD;
        datagram[10] = 1; // record sequence_number
        datagram[11] = (byte)(body.Length >> 8);
        datagram[12] = (byte)body.Length;
        body.CopyTo(datagram, DtlsLimits.RecordHeaderLength);
        clientLower.Send(datagram);
        await Task.Delay(50);

        var clientTask = client.HandshakeAsync();

        await Task.WhenAll(serverTask, clientTask).WaitAsync(TimeSpan.FromSeconds(15));
        server.State.Should().Be(DtlsTransportState.Connected);
        client.State.Should().Be(DtlsTransportState.Connected);

        clientLower.Dispose();
        serverLower.Dispose();
    }

    /// <summary>
    /// A malformed handshake fragment header at epoch 0 is unauthenticated garbage and must be
    /// discarded, not treated as a fatal protocol error (RFC 6347 §4.1.2.7).
    /// </summary>
    [Fact]
    public async Task A_malformed_epoch_zero_handshake_fragment_is_discarded()
    {
        using var serverCertificate = DtlsCertificate.GenerateSelfSigned("server");
        using var clientCertificate = DtlsCertificate.GenerateSelfSigned("client");
        var (serverLower, clientLower) = LoopbackDatagramTransport.CreatePair();

        using var server = new DtlsTransport(serverLower, new DtlsConfig
        {
            Role = DtlsRole.Server,
            Certificate = serverCertificate,
            ExpectedRemoteFingerprintSha256 = clientCertificate.Sha256Fingerprint,
            HandshakeTimeout = TimeSpan.FromSeconds(8),
            Logger = NullLogger.Instance,
        });

        using var client = new DtlsTransport(clientLower, new DtlsConfig
        {
            Role = DtlsRole.Client,
            Certificate = clientCertificate,
            ExpectedRemoteFingerprintSha256 = serverCertificate.Sha256Fingerprint,
            HandshakeTimeout = TimeSpan.FromSeconds(8),
            Logger = NullLogger.Instance,
        });

        var serverTask = server.HandshakeAsync();

        // A handshake record whose body is three bytes: too short to be a fragment header at all.
        byte[] malformed = [0x16, 0xFE, 0xFD, 0x00, 0x00, 0, 0, 0, 0, 0, 1, 0x00, 0x03, 0x0B, 0x00, 0x00];
        clientLower.Send(malformed);
        await Task.Delay(50);

        var clientTask = client.HandshakeAsync();

        await Task.WhenAll(serverTask, clientTask).WaitAsync(TimeSpan.FromSeconds(15));
        server.State.Should().Be(DtlsTransportState.Connected);
        client.State.Should().Be(DtlsTransportState.Connected);

        clientLower.Dispose();
        serverLower.Dispose();
    }

    /// <summary>
    /// A blank expected fingerprint must not be silently treated as "no pinning". It used to be:
    /// the certificate check short-circuited on <c>IsNullOrWhiteSpace</c> while the two
    /// certificate-required checks tested only for null, so the transport demanded a peer
    /// certificate, published its fingerprint and completed the handshake having compared nothing.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public void A_blank_expected_fingerprint_is_refused_rather_than_treated_as_no_pinning(string blank)
    {
        using var certificate = DtlsCertificate.GenerateSelfSigned("local");
        var (left, right) = LoopbackDatagramTransport.CreatePair();

        try
        {
            var construct = () => new DtlsTransport(left, new DtlsConfig
            {
                Role = DtlsRole.Server,
                Certificate = certificate,
                ExpectedRemoteFingerprintSha256 = blank,
                Logger = NullLogger.Instance,
            });

            construct.Should().Throw<ArgumentException>()
                .WithMessage("*blank string is not a pin*");
        }
        finally
        {
            left.Dispose();
            right.Dispose();
        }
    }
}
