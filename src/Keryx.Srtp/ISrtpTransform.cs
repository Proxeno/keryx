namespace Keryx.Srtp;

/// <summary>
/// The profile-specific half of SRTP: turning a parsed packet plus its index into protected bytes
/// and back. Index estimation, replay protection and per-SSRC bookkeeping live in the contexts and
/// are shared by every profile.
/// </summary>
internal interface ISrtpTransform : IDisposable
{
    /// <summary>Bytes added to an RTP packet (the authentication tag).</summary>
    int RtpOverhead { get; }

    /// <summary>Bytes added to an RTCP packet (the E-flag/index word plus the authentication tag).</summary>
    int RtcpOverhead { get; }

    /// <summary>
    /// Shortest protected RTCP packet this profile can produce: the eight-octet RTCP header plus
    /// <see cref="RtcpOverhead"/>.
    /// </summary>
    int MinimumProtectedRtcpLength { get; }

    /// <summary>
    /// Offset of the 32-bit E-flag/SRTCP-index word within a protected RTCP packet. RFC 3711
    /// Section 3.4 places it before the authentication tag; RFC 7714 Section 17 places it after the
    /// AEAD tag, at the very end of the packet.
    /// </summary>
    int SrtcpIndexWordOffset(int packetLength);

    /// <summary>Encrypts the RTP payload and appends the authentication tag; returns the protected length.</summary>
    int ProtectRtp(
        ReadOnlySpan<byte> packet,
        int headerLength,
        uint ssrc,
        uint rolloverCounter,
        ushort sequenceNumber,
        Span<byte> output);

    /// <summary>
    /// Verifies the authentication tag and decrypts the payload. Returns false, without throwing,
    /// when the tag does not verify.
    /// </summary>
    bool TryUnprotectRtp(
        ReadOnlySpan<byte> packet,
        int headerLength,
        uint ssrc,
        uint rolloverCounter,
        ushort sequenceNumber,
        Span<byte> output,
        out int length);

    /// <summary>
    /// Encrypts the RTCP payload when <paramref name="encrypt"/> is set, appends the E-flag/index
    /// word and then the authentication tag; returns the protected length. SRTP contexts always
    /// pass <see langword="true"/>; the flag exists so the E = 0 receive path can be exercised.
    /// </summary>
    int ProtectRtcp(ReadOnlySpan<byte> packet, uint ssrc, uint index, bool encrypt, Span<byte> output);

    /// <summary>
    /// Verifies the authentication tag over the packet including its E-flag/index word and, when
    /// <paramref name="encrypted"/> is set, decrypts the payload. Returns false on tag mismatch.
    /// </summary>
    bool TryUnprotectRtcp(
        ReadOnlySpan<byte> packet,
        uint ssrc,
        uint index,
        bool encrypted,
        Span<byte> output,
        out int length);
}
