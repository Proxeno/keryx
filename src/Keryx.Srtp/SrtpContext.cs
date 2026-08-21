using Keryx.Core;

namespace Keryx.Srtp;

/// <summary>
/// Both directions of SRTP protection for one media transport: an outbound
/// <see cref="SrtpEncryptContext"/> and an inbound <see cref="SrtpDecryptContext"/>.
/// </summary>
/// <remarks>
/// This is the type a PeerConnection normally holds. It handles an entire rtcp-mux / BUNDLE
/// transport: any number of SSRCs in either direction, each with independent rollover counters and
/// replay lists. Instances are not thread-safe.
/// </remarks>
public sealed class SrtpContext : IDisposable
{
    private bool _disposed;

    /// <summary>Creates a bidirectional context from per-direction master keying material.</summary>
    /// <param name="profile">The negotiated protection profile.</param>
    /// <param name="localKeys">Master key and salt used to protect outbound packets.</param>
    /// <param name="remoteKeys">Master key and salt used to unprotect inbound packets.</param>
    /// <param name="logger">Optional logger; defaults to <see cref="NullLogger"/>.</param>
    public SrtpContext(
        SrtpProtectionProfile profile,
        SrtpSessionKeys localKeys,
        SrtpSessionKeys remoteKeys,
        IKeryxLogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(profile);
        Profile = profile;
        Outbound = new SrtpEncryptContext(profile, localKeys, logger);
        try
        {
            Inbound = new SrtpDecryptContext(profile, remoteKeys, logger);
        }
        catch
        {
            Outbound.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates a bidirectional context from a DTLS-SRTP exporter block, splitting it per RFC 5764
    /// Section 4.2 according to the role the local endpoint played in the handshake.
    /// </summary>
    /// <param name="profile">The negotiated protection profile.</param>
    /// <param name="keyingMaterial">
    /// The exporter output, <c>client_key || server_key || client_salt || server_salt</c>
    /// (60 bytes for <see cref="SrtpProtectionProfile.Aes128CmHmacSha1_80"/>).
    /// </param>
    /// <param name="role">Whether the local endpoint was the DTLS client or server.</param>
    /// <param name="logger">Optional logger; defaults to <see cref="NullLogger"/>.</param>
    public static SrtpContext CreateFromDtlsKeyingMaterial(
        SrtpProtectionProfile profile,
        ReadOnlySpan<byte> keyingMaterial,
        DtlsSrtpRole role,
        IKeryxLogger? logger = null)
    {
        var pair = DtlsSrtpKeyMaterial.Split(profile, keyingMaterial, role);
        return new SrtpContext(profile, pair.Local, pair.Remote, logger);
    }

    /// <summary>The protection profile in force.</summary>
    public SrtpProtectionProfile Profile { get; }

    /// <summary>Protects packets the local endpoint sends.</summary>
    public SrtpEncryptContext Outbound { get; }

    /// <summary>Unprotects packets the local endpoint receives.</summary>
    public SrtpDecryptContext Inbound { get; }

    /// <inheritdoc cref="SrtpEncryptContext.ProtectRtp"/>
    public int ProtectRtp(ReadOnlySpan<byte> rtpPacket, Span<byte> output) => Outbound.ProtectRtp(rtpPacket, output);

    /// <inheritdoc cref="SrtpEncryptContext.ProtectRtcp"/>
    public int ProtectRtcp(ReadOnlySpan<byte> rtcpPacket, Span<byte> output) => Outbound.ProtectRtcp(rtcpPacket, output);

    /// <inheritdoc cref="SrtpDecryptContext.TryUnprotectRtp"/>
    public bool TryUnprotectRtp(ReadOnlySpan<byte> srtpPacket, Span<byte> output, out int length) =>
        Inbound.TryUnprotectRtp(srtpPacket, output, out length);

    /// <inheritdoc cref="SrtpDecryptContext.TryUnprotectRtcp"/>
    public bool TryUnprotectRtcp(ReadOnlySpan<byte> srtcpPacket, Span<byte> output, out int length) =>
        Inbound.TryUnprotectRtcp(srtcpPacket, output, out length);

    /// <summary>Releases both directions.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Outbound.Dispose();
        Inbound.Dispose();
    }
}
