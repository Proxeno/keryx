using System.Security.Cryptography;
using Keryx.Srtp;

namespace Keryx.Broadcast;

/// <summary>
/// One public broadcast's shared SRTP master key and salt (<c>broadcast-scale.md</c> §5). Every viewer
/// of the broadcast receives <b>this same key</b> and, holding it, can both decrypt and — because SRTP
/// AEAD is symmetric — forge broadcast media. Constructing one is therefore an explicit assertion that
/// the content is public, and the type is shaped so that assertion cannot be made by accident.
/// </summary>
/// <remarks>
/// <para>
/// <b>Threat model (spec §5.4), stated in code so it cannot be missed.</b> Under a shared key the SRTP
/// guarantee degrades from a pairwise SFU↔viewer channel to a <i>group</i> guarantee: confidentiality
/// within the viewer set is gone by design (any viewer can read the stream — that is the product, the
/// same trust model as a public HLS/DASH CDN), and per-viewer media <i>authentication</i> is traded for
/// scale (any keyholder who also has the network position can forge media toward another viewer). This
/// is acceptable <b>only</b> for public broadcasts. It must never be used for private rooms, 1:1 calls,
/// or any room where participants have different rights to the media. The ingest leg
/// (broadcaster→SFU) is unaffected — it keeps its own DTLS-SRTP keys — and every per-viewer path viewer
/// keeps its own keys; only the shared broadcast egress rides this key.
/// </para>
/// <para>
/// <b>Structural boundary.</b> The only way to obtain an instance is
/// <see cref="CreateForPublicContent(SrtpProtectionProfile)"/> (or <see cref="RotateEpoch"/> from one):
/// the word "public" is unavoidable at every call site, and the key is minted from a CSPRNG — it is
/// <i>never</i> derived from, or mixed with, any connection's DTLS-exported material (spec §5.4
/// invariant 1). There is no general constructor, no way to build one from a per-connection secret, and
/// no in-place mutation of the key bytes.
/// </para>
/// <para>Instances are immutable and safe to share for read (export/derive) across threads. Dispose to
/// zero the key material when the broadcast ends.</para>
/// </remarks>
public sealed class PublicBroadcastKey : IDisposable
{
    private readonly byte[] _masterKey;
    private readonly byte[] _masterSalt;
    private bool _disposed;

    private PublicBroadcastKey(SrtpProtectionProfile profile, byte[] masterKey, byte[] masterSalt, int epoch)
    {
        Profile = profile;
        _masterKey = masterKey;
        _masterSalt = masterSalt;
        Epoch = epoch;
    }

    /// <summary>
    /// Mints a fresh, random shared key for a <b>public</b> broadcast at epoch 0. This is the only way to
    /// construct a <see cref="PublicBroadcastKey"/>; naming it asserts, at the call site, that the media
    /// it protects is public content (spec §5.4). The key and salt come from
    /// <see cref="RandomNumberGenerator"/> and are never derived from any peer's DTLS handshake.
    /// </summary>
    /// <param name="profile">The SRTP protection profile the broadcast will use.</param>
    /// <returns>A new shared key at epoch 0.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="profile"/> is null.</exception>
    public static PublicBroadcastKey CreateForPublicContent(SrtpProtectionProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return Mint(profile, epoch: 0);
    }

    /// <summary>The SRTP protection profile this key is used with.</summary>
    public SrtpProtectionProfile Profile { get; }

    /// <summary>
    /// The epoch of this key: a monotonic counter that increments on each <see cref="RotateEpoch"/>.
    /// Rotation is on demand (e.g. a stream restart), never on viewer join/leave — public content does
    /// not need per-membership rekeying (spec §5.1).
    /// </summary>
    public int Epoch { get; }

    /// <summary>
    /// Mints the <i>next</i> epoch: a brand-new random key and salt at <c>Epoch + 1</c>. The current
    /// instance is left intact and undisposed so the SFU and its viewers can hold both epochs across the
    /// switch (the receiver has no MKI to tell them apart, so it tries both — spec §5.1). Distribute the
    /// new key over each viewer's data channel, switch the sender at an RTP-timestamp boundary, then
    /// dispose the old key once no packet under it can still be in flight.
    /// </summary>
    /// <returns>A new shared key at the next epoch, sharing this key's profile.</returns>
    /// <exception cref="ObjectDisposedException">This key has been disposed.</exception>
    public PublicBroadcastKey RotateEpoch()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return Mint(Profile, Epoch + 1);
    }

    /// <summary>
    /// Exports this key's material for delivery to a viewer. The export is the payload the SFU sends over
    /// each viewer's already-DTLS-authenticated data channel (spec §5.1); it carries a copy of the key
    /// bytes, so treat it as secret and dispose the viewer's installed copy when done.
    /// </summary>
    /// <returns>A transferable snapshot of this key's epoch, profile and material.</returns>
    /// <exception cref="ObjectDisposedException">This key has been disposed.</exception>
    public PublicBroadcastKeyExport Export()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new PublicBroadcastKeyExport(Epoch, Profile.Kind, _masterKey, _masterSalt);
    }

    // The SRTP session keys this shared key protects (or unprotects) the broadcast with. Internal: the
    // key bytes never leave the assembly except through the deliberate, secret Export() channel.
    internal SrtpSessionKeys ToSessionKeys()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new SrtpSessionKeys(_masterKey, _masterSalt);
    }

    private static PublicBroadcastKey Mint(SrtpProtectionProfile profile, int epoch)
    {
        var key = new byte[profile.MasterKeyLength];
        var salt = new byte[profile.MasterSaltLength];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(salt);
        return new PublicBroadcastKey(profile, key, salt, epoch);
    }

    /// <summary>Zeroes the key and salt bytes.</summary>
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
}
