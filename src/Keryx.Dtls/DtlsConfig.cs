using Keryx.Core;

namespace Keryx.Dtls;

/// <summary>Everything a <see cref="DtlsTransport"/> needs to run a handshake.</summary>
/// <remarks>
/// A config is read once when the transport is constructed; mutating it afterwards has no effect.
/// The <see cref="Certificate"/> is not owned by the transport and is not disposed with it.
/// </remarks>
public sealed class DtlsConfig
{
    /// <summary>Which side of the handshake this endpoint plays. Defaults to <see cref="DtlsRole.Server"/>.</summary>
    public DtlsRole Role { get; init; } = DtlsRole.Server;

    /// <summary>The local certificate and private key. Required.</summary>
    public required DtlsCertificate Certificate { get; init; }

    /// <summary>
    /// SRTP protection profiles to offer (client) or to choose from (server), most preferred first.
    /// An empty list disables the <c>use_srtp</c> extension entirely.
    /// </summary>
    public IReadOnlyList<SrtpProtectionProfile> SrtpProfiles { get; init; } =
    [
        SrtpProtectionProfile.Aes128CmHmacSha1Tag80,
        SrtpProtectionProfile.AeadAes128Gcm,
    ];

    /// <summary>
    /// The peer certificate fingerprint learned from signalling (SDP <c>a=fingerprint:sha-256</c>).
    /// When set, the peer's certificate is checked against it during the handshake and a mismatch
    /// aborts with a <c>bad_certificate</c> alert. Accepts any separator style and letter case.
    /// </summary>
    /// <remarks>
    /// This check is the entire trust anchor of WebRTC's security model. Leaving it null accepts any
    /// self-signed peer certificate and provides confidentiality against a passive attacker only.
    /// </remarks>
    public string? ExpectedRemoteFingerprintSha256 { get; init; }

    /// <summary>How long <see cref="DtlsTransport.HandshakeAsync"/> waits before failing. Defaults to 30 seconds.</summary>
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Initial retransmission timeout; doubles on every expiry up to <see cref="MaxRetransmitTimeout"/>.</summary>
    public TimeSpan InitialRetransmitTimeout { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>Ceiling for the exponential retransmission backoff (RFC 6347 §4.2.4.1).</summary>
    public TimeSpan MaxRetransmitTimeout { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// As a server, refuse the handshake unless the client presents a certificate. WebRTC always
    /// uses mutual authentication, so this defaults to true.
    /// </summary>
    public bool RequirePeerCertificate { get; init; } = true;

    /// <summary>
    /// As a server, answer the first (cookieless) <c>ClientHello</c> with a
    /// <c>HelloVerifyRequest</c> carrying a stateless cookie and only continue once the client
    /// echoes a valid cookie in a second <c>ClientHello</c> (RFC 6347 §4.2.1).
    /// </summary>
    /// <remarks>
    /// The cookie round-trip proves the client can receive at its claimed source before the server
    /// allocates any handshake state, which is the anti-spoofing / amplification defence a generic
    /// DTLS server needs. In WebRTC the exchange is unnecessary — DTLS only starts once ICE has
    /// already validated the peer's address — so this defaults to <see langword="false"/> and the
    /// WebRTC handshake is byte-for-byte unchanged. Turn it on for non-WebRTC or defence-in-depth
    /// deployments. It has no effect in the <see cref="DtlsRole.Client"/> role, which already honours
    /// a server-issued <c>HelloVerifyRequest</c> whether or not this is set.
    /// </remarks>
    public bool RequireDtlsCookie { get; init; }

    /// <summary>
    /// Largest datagram Keryx will emit. Clamped to the lower transport's
    /// <see cref="IDatagramTransport.MaxDatagramSize"/>. Defaults to 1200 bytes, the value WebRTC
    /// implementations use to stay inside the path MTU.
    /// </summary>
    public int MaxDatagramSize { get; init; } = DtlsLimits.DefaultMtu;

    /// <summary>Diagnostics sink. Defaults to <see cref="NullLogger"/>.</summary>
    public IKeryxLogger Logger { get; init; } = NullLogger.Instance;

    /// <summary>
    /// Overrides the cipher suites offered (client) or preferred (server), most preferred first. Null
    /// uses Keryx's default preference for the certificate key type. Intended for tests; the default
    /// already offers every suite Keryx implements.
    /// </summary>
    internal IReadOnlyList<ushort>? OfferedCipherSuites { get; init; }

    /// <summary>
    /// Overrides the ECDHE named groups offered (client) or preferred (server), most preferred first.
    /// Null uses Keryx's default curve preference. Intended for tests.
    /// </summary>
    internal IReadOnlyList<ushort>? OfferedNamedGroups { get; init; }
}
