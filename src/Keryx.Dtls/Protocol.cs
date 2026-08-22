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

internal static class CipherSuites
{
    public const ushort TlsEcdheEcdsaWithAes128GcmSha256 = 0xC02B;
    public const ushort TlsEcdheRsaWithAes128GcmSha256 = 0xC02F;

    /// <summary>TLS_EMPTY_RENEGOTIATION_INFO_SCSV — a signalling suite, never selectable.</summary>
    public const ushort EmptyRenegotiationInfoScsv = 0x00FF;

    public static bool IsSupported(ushort suite) =>
        suite is TlsEcdheEcdsaWithAes128GcmSha256 or TlsEcdheRsaWithAes128GcmSha256;

    public static string Name(ushort suite) => suite switch
    {
        TlsEcdheEcdsaWithAes128GcmSha256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        TlsEcdheRsaWithAes128GcmSha256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        _ => $"0x{suite:X4}",
    };
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
    /// <summary>secp256r1 / NIST P-256 — the only group Keryx offers; the BCL has no X25519 agreement.</summary>
    public const ushort Secp256r1 = 23;

    public const ushort Secp384r1 = 24;
    public const ushort X25519 = 29;
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
