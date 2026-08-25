using System.Buffers.Binary;
using System.Security.Cryptography;
using Keryx.Srtp;

namespace Keryx.Broadcast;

/// <summary>
/// A transferable snapshot of a <see cref="PublicBroadcastKey"/>: the epoch, protection profile and
/// master key/salt a viewer needs to decrypt the shared broadcast. Produced by
/// <see cref="PublicBroadcastKey.Export"/> and installed on the receive side with
/// <c>PeerConnectionConfig.InstallPublicBroadcastReceiveKey</c>.
/// </summary>
/// <remarks>
/// This object carries a copy of secret key bytes. It is meant to travel over the confidential,
/// per-viewer authenticated channel that already exists — the viewer's DTLS-protected data channel
/// (spec §5.1) — encoded with <see cref="PublicBroadcastKeyMessage"/>. It is never SDP and never a
/// signaling-server-trusted value beyond what the data channel already implies. Treat it as a secret.
/// </remarks>
public sealed class PublicBroadcastKeyExport : IDisposable
{
    private readonly byte[] _masterKey;
    private readonly byte[] _masterSalt;
    private bool _disposed;

    internal PublicBroadcastKeyExport(
        int epoch,
        SrtpProtectionProfileKind profileKind,
        ReadOnlySpan<byte> masterKey,
        ReadOnlySpan<byte> masterSalt)
    {
        Epoch = epoch;
        ProfileKind = profileKind;
        _masterKey = masterKey.ToArray();
        _masterSalt = masterSalt.ToArray();
    }

    /// <summary>The epoch of the exported key (see <see cref="PublicBroadcastKey.Epoch"/>).</summary>
    public int Epoch { get; }

    /// <summary>The SRTP protection profile the key is used with.</summary>
    public SrtpProtectionProfileKind ProfileKind { get; }

    /// <summary>The protection profile the key is used with.</summary>
    public SrtpProtectionProfile Profile => SrtpProtectionProfile.ForKind(ProfileKind);

    // The master key and salt. Internal so the bytes are reachable only from the key-install and wire-encode
    // seams, not from arbitrary application code holding the export.
    internal ReadOnlyMemory<byte> MasterKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _masterKey;
        }
    }

    internal ReadOnlyMemory<byte> MasterSalt
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _masterSalt;
        }
    }

    internal SrtpSessionKeys ToSessionKeys()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new SrtpSessionKeys(_masterKey, _masterSalt);
    }

    /// <summary>
    /// Zeroes this export's copy of the key and salt bytes. The export carries secret material (spec §5.1);
    /// dispose it once the key has been installed on the receiver or encoded for delivery so the plaintext
    /// bytes do not linger in the heap. Disposing does not affect the <see cref="PublicBroadcastKey"/> it
    /// came from, any other export, or an already-installed decrypt context — each holds its own copy.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(_masterKey);
        CryptographicOperations.ZeroMemory(_masterSalt);
    }

    /// <summary>A redacted description; key bytes are never rendered.</summary>
    public override string ToString() =>
        $"PublicBroadcastKeyExport {{ Epoch = {Epoch}, Profile = {Profile.Name}, "
        + $"Key = {_masterKey.Length} bytes, Salt = {_masterSalt.Length} bytes }}";
}

/// <summary>
/// The Keryx-defined control message that carries a <see cref="PublicBroadcastKeyExport"/> and the
/// broadcast SSRC(s) it applies to, for delivery over a viewer's data channel (spec §5.1). It is not an
/// SDP or IETF-standard construct: shared-key mode is Keryx-defined and not interoperable with stock
/// browsers, so this is a private wire format between Keryx endpoints.
/// </summary>
/// <remarks>
/// The message is self-describing and length-checked so it cannot be confused with application data
/// channel traffic: a 4-byte magic and version byte lead every frame. It carries the SSRC scope so the
/// receiver applies the shared key <b>only</b> to the enumerated broadcast SSRCs and never to any other
/// (e.g. private) m-line on the same connection — the structural client-side half of the boundary.
/// </remarks>
public static class PublicBroadcastKeyMessage
{
    // "KBK" + version 1. A four-byte tag that no RTP/RTCP/STUN/DTLS first byte collides with and that an
    // application is exceedingly unlikely to send by accident on a control channel it dedicates to this.
    private static readonly byte[] Magic = [(byte)'K', (byte)'B', (byte)'K', 0x01];

    /// <summary>Encodes a key export and its broadcast SSRC scope into a self-describing control frame.</summary>
    /// <param name="export">The key export to deliver.</param>
    /// <param name="broadcastSsrcs">The broadcast SSRC(s) the key decrypts. Must be non-empty.</param>
    /// <returns>The encoded frame, ready to send over a data channel.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="broadcastSsrcs"/> is empty.</exception>
    public static byte[] Encode(PublicBroadcastKeyExport export, IReadOnlyList<uint> broadcastSsrcs)
    {
        ArgumentNullException.ThrowIfNull(export);
        ArgumentNullException.ThrowIfNull(broadcastSsrcs);
        if (broadcastSsrcs.Count == 0)
        {
            throw new ArgumentException("A broadcast key message must name at least one broadcast SSRC.", nameof(broadcastSsrcs));
        }

        // The SSRC count rides in a single byte on the wire, so more than 255 SSRCs cannot be encoded
        // without silently truncating the count and producing a frame the decoder mis-parses. Refuse it up
        // front. A broadcast tier is one SSRC; even a full simulcast set is a handful — 255 is a generous cap.
        if (broadcastSsrcs.Count > byte.MaxValue)
        {
            throw new ArgumentException(
                $"A broadcast key message carries at most {byte.MaxValue} SSRCs (the on-wire count is one byte), "
                + $"but {broadcastSsrcs.Count} were supplied.",
                nameof(broadcastSsrcs));
        }

        var key = export.MasterKey.Span;
        var salt = export.MasterSalt.Span;

        // magic(4) | epoch(4) | profile(2) | ssrcCount(1) | ssrcs(4*n) | keyLen(1) | key | saltLen(1) | salt
        var length = 4 + 4 + 2 + 1 + (4 * broadcastSsrcs.Count) + 1 + key.Length + 1 + salt.Length;
        var buffer = new byte[length];
        var span = buffer.AsSpan();

        Magic.CopyTo(span);
        var offset = 4;
        BinaryPrimitives.WriteInt32BigEndian(span[offset..], export.Epoch);
        offset += 4;
        BinaryPrimitives.WriteUInt16BigEndian(span[offset..], (ushort)export.ProfileKind);
        offset += 2;
        span[offset++] = (byte)broadcastSsrcs.Count;
        for (var i = 0; i < broadcastSsrcs.Count; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(span[offset..], broadcastSsrcs[i]);
            offset += 4;
        }

        span[offset++] = (byte)key.Length;
        key.CopyTo(span[offset..]);
        offset += key.Length;
        span[offset++] = (byte)salt.Length;
        salt.CopyTo(span[offset..]);

        return buffer;
    }

    /// <summary>
    /// Attempts to decode a data channel frame as a broadcast key message. Returns false — never throws —
    /// for any frame that is not a well-formed key message, so it can be tried against arbitrary inbound
    /// data channel traffic.
    /// </summary>
    /// <param name="frame">The received data channel payload.</param>
    /// <param name="export">On success, the decoded key export.</param>
    /// <param name="broadcastSsrcs">On success, the broadcast SSRC scope.</param>
    /// <returns>True when the frame decoded as a broadcast key message.</returns>
    public static bool TryDecode(
        ReadOnlySpan<byte> frame,
        out PublicBroadcastKeyExport? export,
        out IReadOnlyList<uint> broadcastSsrcs)
    {
        export = null;
        broadcastSsrcs = [];

        if (frame.Length < 12 || !frame[..4].SequenceEqual(Magic))
        {
            return false;
        }

        var offset = 4;
        var epoch = BinaryPrimitives.ReadInt32BigEndian(frame[offset..]);
        offset += 4;
        var profileValue = BinaryPrimitives.ReadUInt16BigEndian(frame[offset..]);
        offset += 2;
        if (!Enum.IsDefined((SrtpProtectionProfileKind)profileValue))
        {
            return false;
        }

        var ssrcCount = frame[offset++];
        if (ssrcCount == 0 || frame.Length < offset + (4 * ssrcCount) + 2)
        {
            return false;
        }

        var ssrcs = new uint[ssrcCount];
        for (var i = 0; i < ssrcCount; i++)
        {
            ssrcs[i] = BinaryPrimitives.ReadUInt32BigEndian(frame[offset..]);
            offset += 4;
        }

        var keyLen = frame[offset++];
        if (frame.Length < offset + keyLen + 1)
        {
            return false;
        }

        var keyBytes = frame.Slice(offset, keyLen);
        offset += keyLen;
        var saltLen = frame[offset++];
        if (frame.Length < offset + saltLen)
        {
            return false;
        }

        var saltBytes = frame.Slice(offset, saltLen);

        export = new PublicBroadcastKeyExport(epoch, (SrtpProtectionProfileKind)profileValue, keyBytes, saltBytes);
        broadcastSsrcs = ssrcs;
        return true;
    }
}
