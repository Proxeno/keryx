namespace Keryx.Dtls;

/// <summary>
/// SRTP protection profiles negotiated through the DTLS <c>use_srtp</c> extension (RFC 5764 §4.1.2).
/// </summary>
/// <remarks>
/// The numeric values are the IANA "SRTP Protection Profile" code points carried on the wire.
/// After a successful handshake the SRTP keying material is derived with
/// <see cref="DtlsTransport.ExportKeyingMaterial(string, int)"/> using the label
/// <c>EXTRACTOR-dtls_srtp</c>.
/// </remarks>
public enum SrtpProtectionProfile : ushort
{
    /// <summary>No profile was negotiated (the peer did not offer <c>use_srtp</c>, or offered none in common).</summary>
    None = 0x0000,

    /// <summary><c>SRTP_AES128_CM_HMAC_SHA1_80</c>: AES-128 counter mode with an 80-bit HMAC-SHA1 tag. 60 bytes of keying material.</summary>
    Aes128CmHmacSha1Tag80 = 0x0001,

    /// <summary><c>SRTP_AES128_CM_HMAC_SHA1_32</c>: AES-128 counter mode with a 32-bit HMAC-SHA1 tag. 60 bytes of keying material.</summary>
    Aes128CmHmacSha1Tag32 = 0x0002,

    /// <summary><c>SRTP_AEAD_AES_128_GCM</c> (RFC 7714): AES-128-GCM. 56 bytes of keying material.</summary>
    AeadAes128Gcm = 0x0007,

    /// <summary><c>SRTP_AEAD_AES_256_GCM</c> (RFC 7714): AES-256-GCM. 88 bytes of keying material.</summary>
    AeadAes256Gcm = 0x0008,
}

/// <summary>Helpers for <see cref="SrtpProtectionProfile"/>.</summary>
public static class SrtpProtectionProfileExtensions
{
    /// <summary>
    /// Total number of bytes that must be exported from the DTLS connection for
    /// <paramref name="profile"/>: <c>2 * (key length + salt length)</c>.
    /// </summary>
    /// <param name="profile">The negotiated profile.</param>
    /// <returns>The exporter length in bytes, or 0 for <see cref="SrtpProtectionProfile.None"/>.</returns>
    public static int KeyingMaterialLength(this SrtpProtectionProfile profile) => profile switch
    {
        SrtpProtectionProfile.Aes128CmHmacSha1Tag80 => 60,
        SrtpProtectionProfile.Aes128CmHmacSha1Tag32 => 60,
        SrtpProtectionProfile.AeadAes128Gcm => 56,
        SrtpProtectionProfile.AeadAes256Gcm => 88,
        _ => 0,
    };
}
