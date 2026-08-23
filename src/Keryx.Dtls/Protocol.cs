namespace Keryx.Dtls;

/// <summary>DTLS record content types (RFC 5246 §6.2.1).</summary>
internal enum ContentType : byte
{
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

/// <summary>Handshake message types (RFC 5246 §7.4, RFC 6347 §4.3.2).</summary>
internal enum HandshakeType : byte
{
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3,
    NewSessionTicket = 4,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
}

internal static class ProtocolVersions
{
    /// <summary>
    /// DTLS 1.0 — {254, 255}. Accepted as a <em>record-layer</em> version only, because RFC 6347
    /// §4.1 lets an initial ClientHello record carry it. It is never acceptable as a negotiated
    /// version: a ClientHello whose <c>client_version</c> is DTLS 1.0 is refused with
    /// <c>protocol_version</c>.
    /// </summary>
    public const ushort Dtls10 = 0xFEFF;

    /// <summary>DTLS 1.2 — {254, 253}.</summary>
    public const ushort Dtls12 = 0xFEFD;
}

/// <summary>The AEAD primitive a cipher suite protects records with.</summary>
internal enum AeadAlgorithm
{
    /// <summary>AES-GCM (RFC 5288 / RFC 5289): 4-byte fixed IV plus an 8-byte explicit nonce.</summary>
    AesGcm,

    /// <summary>ChaCha20-Poly1305 (RFC 7905): a 12-byte fixed IV XORed with the record sequence number.</summary>
    ChaCha20Poly1305,
}

/// <summary>
/// The parameters of one DTLS 1.2 AEAD cipher suite: its record protection primitive, key/IV sizes,
/// per-record overhead, PRF hash, and which certificate key type authenticates it.
/// </summary>
internal readonly record struct CipherSuiteDescription(
    ushort Id,
    string Name,
    bool RequiresEcdsaCertificate,
    AeadAlgorithm Aead,
    int KeyLength,
    int FixedIvLength,
    int RecordOverhead,
    byte PrfHash);

internal static class CipherSuites
{
    public const ushort TlsEcdheEcdsaWithAes128GcmSha256 = 0xC02B;
    public const ushort TlsEcdheRsaWithAes128GcmSha256 = 0xC02F;
    public const ushort TlsEcdheEcdsaWithAes256GcmSha384 = 0xC02C;
    public const ushort TlsEcdheRsaWithAes256GcmSha384 = 0xC030;
    public const ushort TlsEcdheEcdsaWithChaCha20Poly1305Sha256 = 0xCCA9;
    public const ushort TlsEcdheRsaWithChaCha20Poly1305Sha256 = 0xCCA8;

    /// <summary>TLS_EMPTY_RENEGOTIATION_INFO_SCSV — a signalling suite, never selectable.</summary>
    public const ushort EmptyRenegotiationInfoScsv = 0x00FF;

    // AES-GCM: 4-byte fixed IV + 8-byte explicit nonce + 16-byte tag => 24 bytes of record overhead.
    // ChaCha20-Poly1305 (RFC 7905): a 12-byte fixed IV, no explicit nonce, 16-byte tag => 16 bytes.
    private const int GcmOverhead = 8 + 16;
    private const int ChaChaOverhead = 16;

    /// <summary>
    /// The suites Keryx offers as a client, and prefers as a server, most preferred first. AES-256-GCM
    /// and ChaCha20-Poly1305 sit above AES-128-GCM; ECDSA suites are used with an ECDSA certificate and
    /// the RSA suites with an RSA certificate.
    /// </summary>
    public static ushort[] PreferenceFor(bool ecdsaCertificate) => ecdsaCertificate
        ?
        [
            TlsEcdheEcdsaWithAes256GcmSha384,
            TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
            TlsEcdheEcdsaWithAes128GcmSha256,
        ]
        :
        [
            TlsEcdheRsaWithAes256GcmSha384,
            TlsEcdheRsaWithChaCha20Poly1305Sha256,
            TlsEcdheRsaWithAes128GcmSha256,
        ];

    public static bool IsSupported(ushort suite) => Describe(suite) is not null;

    /// <summary>The parameters of <paramref name="suite"/>, or null when Keryx does not implement it.</summary>
    public static CipherSuiteDescription? Describe(ushort suite) => suite switch
    {
        TlsEcdheEcdsaWithAes128GcmSha256 => new CipherSuiteDescription(
            suite, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", true, AeadAlgorithm.AesGcm, 16, 4, GcmOverhead, HashAlgorithms.Sha256),
        TlsEcdheRsaWithAes128GcmSha256 => new CipherSuiteDescription(
            suite, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false, AeadAlgorithm.AesGcm, 16, 4, GcmOverhead, HashAlgorithms.Sha256),
        TlsEcdheEcdsaWithAes256GcmSha384 => new CipherSuiteDescription(
            suite, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", true, AeadAlgorithm.AesGcm, 32, 4, GcmOverhead, HashAlgorithms.Sha384),
        TlsEcdheRsaWithAes256GcmSha384 => new CipherSuiteDescription(
            suite, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", false, AeadAlgorithm.AesGcm, 32, 4, GcmOverhead, HashAlgorithms.Sha384),
        TlsEcdheEcdsaWithChaCha20Poly1305Sha256 => new CipherSuiteDescription(
            suite, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", true, AeadAlgorithm.ChaCha20Poly1305, 32, 12, ChaChaOverhead, HashAlgorithms.Sha256),
        TlsEcdheRsaWithChaCha20Poly1305Sha256 => new CipherSuiteDescription(
            suite, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", false, AeadAlgorithm.ChaCha20Poly1305, 32, 12, ChaChaOverhead, HashAlgorithms.Sha256),
        _ => null,
    };

    public static string Name(ushort suite) => Describe(suite)?.Name ?? $"0x{suite:X4}";
}

internal static class ExtensionTypes
{
    public const ushort SupportedGroups = 10;
    public const ushort EcPointFormats = 11;
    public const ushort SignatureAlgorithms = 13;
    public const ushort UseSrtp = 14;
    public const ushort ExtendedMasterSecret = 23;
    public const ushort RenegotiationInfo = 0xFF01;
}

internal static class NamedGroups
{
    /// <summary>secp256r1 / NIST P-256 — the universally supported WebRTC curve.</summary>
    public const ushort Secp256r1 = 23;

    /// <summary>secp384r1 / NIST P-384.</summary>
    public const ushort Secp384r1 = 24;

    /// <summary>
    /// x25519 (29) is deliberately NOT offered: the .NET 10 BCL exposes no X25519 key agreement in
    /// <c>System.Security.Cryptography</c>, and Keryx never hand-rolls a curve.
    /// </summary>
    public const ushort X25519 = 29;

    /// <summary>
    /// The elliptic-curve groups Keryx supports for ECDHE, most preferred first. P-384 sits above
    /// P-256; both are exposed by <see cref="System.Security.Cryptography.ECDiffieHellman"/>.
    /// </summary>
    public static ushort[] Preference => [Secp384r1, Secp256r1];

    public static bool IsSupported(ushort group) => group is Secp256r1 or Secp384r1;
}

internal static class EcCurveTypes
{
    public const byte NamedCurve = 3;
}

internal static class ClientCertificateTypes
{
    public const byte RsaSign = 1;
    public const byte EcdsaSign = 64;
}

internal static class HashAlgorithms
{
    public const byte Sha256 = 4;
    public const byte Sha384 = 5;
    public const byte Sha512 = 6;
}

internal static class SignatureAlgorithms
{
    public const byte Rsa = 1;
    public const byte Ecdsa = 3;
}

/// <summary>A TLS 1.2 <c>SignatureAndHashAlgorithm</c> (RFC 5246 §7.4.1.4.1).</summary>
internal readonly record struct SigHashAlgorithm(byte Hash, byte Signature)
{
    public static SigHashAlgorithm EcdsaSha256 => new(HashAlgorithms.Sha256, SignatureAlgorithms.Ecdsa);

    public static SigHashAlgorithm RsaSha256 => new(HashAlgorithms.Sha256, SignatureAlgorithms.Rsa);

    public ushort Encoded => (ushort)((Hash << 8) | Signature);

    public override string ToString() => $"{Signature switch
    {
        SignatureAlgorithms.Rsa => "rsa",
        SignatureAlgorithms.Ecdsa => "ecdsa",
        _ => Signature.ToString(System.Globalization.CultureInfo.InvariantCulture),
    }}_{Hash switch
    {
        HashAlgorithms.Sha256 => "sha256",
        HashAlgorithms.Sha384 => "sha384",
        HashAlgorithms.Sha512 => "sha512",
        _ => Hash.ToString(System.Globalization.CultureInfo.InvariantCulture),
    }}";
}

internal static class DtlsLimits
{
    /// <summary>Record header length: type(1) + version(2) + epoch(2) + sequence(6) + length(2).</summary>
    public const int RecordHeaderLength = 13;

    /// <summary>Handshake header: type(1) + length(3) + message_seq(2) + fragment_offset(3) + fragment_length(3).</summary>
    public const int HandshakeHeaderLength = 12;

    /// <summary>Default target datagram size — comfortably inside the WebRTC path MTU.</summary>
    public const int DefaultMtu = 1200;

    /// <summary>AES-GCM record overhead: 8-byte explicit nonce plus a 16-byte tag.</summary>
    public const int GcmRecordOverhead = 24;

    /// <summary>Largest handshake message Keryx will reassemble, to bound memory from a hostile peer.</summary>
    public const int MaxHandshakeMessageLength = 128 * 1024;

    /// <summary>Largest handshake transcript Keryx will retain, to bound memory from a hostile peer.</summary>
    public const int MaxTranscriptLength = 512 * 1024;

    /// <summary>Verify-data length for every TLS 1.2 suite Keryx implements.</summary>
    public const int VerifyDataLength = 12;
}
