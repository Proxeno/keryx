namespace Keryx.Srtp;

/// <summary>
/// Identifies an SRTP protection profile. The numeric values are the DTLS-SRTP
/// <c>SRTPProtectionProfile</c> code points from the IANA registry established by
/// RFC 5764 Section 4.1.2.
/// </summary>
public enum SrtpProtectionProfileKind
{
    /// <summary>
    /// <c>SRTP_AES128_CM_HMAC_SHA1_80</c> (RFC 5764 Section 4.1.2): AES-128 in SRTP counter mode
    /// (RFC 3711 Section 4.1.1) with HMAC-SHA1 truncated to 80 bits (RFC 3711 Section 4.2.1).
    /// This is the mandatory-to-implement WebRTC profile.
    /// </summary>
    Aes128CmHmacSha1_80 = 0x0001,

    /// <summary>
    /// <c>SRTP_AEAD_AES_128_GCM</c> (RFC 7714 Section 14.2): AES-128-GCM with a 128-bit
    /// authentication tag, using the RFC 3711 AES-CM PRF for key derivation.
    /// </summary>
    AeadAes128Gcm = 0x0007,
}

/// <summary>
/// Describes the cryptographic parameters of an SRTP protection profile: key sizes, salt sizes and
/// the per-packet expansion applied by <see cref="SrtpEncryptContext"/>.
/// </summary>
public sealed class SrtpProtectionProfile
{
    private SrtpProtectionProfile(
        SrtpProtectionProfileKind kind,
        string name,
        int masterKeyLength,
        int masterSaltLength,
        int sessionSaltLength,
        int authKeyLength,
        int tagLength)
    {
        Kind = kind;
        Name = name;
        MasterKeyLength = masterKeyLength;
        MasterSaltLength = masterSaltLength;
        SessionSaltLength = sessionSaltLength;
        AuthenticationKeyLength = authKeyLength;
        TagLength = tagLength;
    }

    /// <summary>
    /// <c>SRTP_AES128_CM_HMAC_SHA1_80</c>: 128-bit master key, 112-bit master salt, 80-bit tag.
    /// </summary>
    public static SrtpProtectionProfile Aes128CmHmacSha1_80 { get; } = new(
        SrtpProtectionProfileKind.Aes128CmHmacSha1_80,
        "SRTP_AES128_CM_HMAC_SHA1_80",
        masterKeyLength: 16,
        masterSaltLength: 14,
        sessionSaltLength: 14,
        authKeyLength: 20,
        tagLength: 10);

    /// <summary>
    /// <c>SRTP_AEAD_AES_128_GCM</c>: 128-bit master key, 96-bit master salt, 128-bit AEAD tag
    /// (RFC 7714 Section 12, Table 2).
    /// </summary>
    public static SrtpProtectionProfile AeadAes128Gcm { get; } = new(
        SrtpProtectionProfileKind.AeadAes128Gcm,
        "SRTP_AEAD_AES_128_GCM",
        masterKeyLength: 16,
        masterSaltLength: 12,
        sessionSaltLength: 12,
        authKeyLength: 0,
        tagLength: 16);

    /// <summary>The profile identifier.</summary>
    public SrtpProtectionProfileKind Kind { get; }

    /// <summary>The registered profile name, e.g. <c>SRTP_AES128_CM_HMAC_SHA1_80</c>.</summary>
    public string Name { get; }

    /// <summary>Length in bytes of the master key supplied by key management.</summary>
    public int MasterKeyLength { get; }

    /// <summary>Length in bytes of the master salt supplied by key management.</summary>
    public int MasterSaltLength { get; }

    /// <summary>Length in bytes of the derived session salt (RFC 3711 label 0x02 / 0x05).</summary>
    public int SessionSaltLength { get; }

    /// <summary>
    /// Length in bytes of the derived session authentication key (RFC 3711 label 0x01 / 0x04), or
    /// zero for AEAD profiles which authenticate with the cipher itself.
    /// </summary>
    public int AuthenticationKeyLength { get; }

    /// <summary>Length in bytes of the authentication tag appended to every protected packet.</summary>
    public int TagLength { get; }

    /// <summary>Number of bytes <see cref="SrtpEncryptContext.ProtectRtp"/> adds to an RTP packet.</summary>
    public int RtpOverhead => TagLength;

    /// <summary>
    /// Number of bytes <see cref="SrtpEncryptContext.ProtectRtcp"/> adds to an RTCP packet: the
    /// 4-byte <c>E</c>-flag/SRTCP-index word (RFC 3711 Section 3.4) plus the tag.
    /// </summary>
    public int RtcpOverhead => SrtcpIndexLength + TagLength;

    /// <summary>Length in bytes of the <c>E</c>-flag/SRTCP-index word appended to every SRTCP packet.</summary>
    public const int SrtcpIndexLength = 4;

    /// <summary>Returns the profile description for <paramref name="kind"/>.</summary>
    /// <param name="kind">The profile to look up.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="kind"/> is not a known profile.</exception>
    public static SrtpProtectionProfile ForKind(SrtpProtectionProfileKind kind) => kind switch
    {
        SrtpProtectionProfileKind.Aes128CmHmacSha1_80 => Aes128CmHmacSha1_80,
        SrtpProtectionProfileKind.AeadAes128Gcm => AeadAes128Gcm,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unsupported SRTP protection profile."),
    };

    /// <summary>Returns <see cref="Name"/>.</summary>
    public override string ToString() => Name;
}
