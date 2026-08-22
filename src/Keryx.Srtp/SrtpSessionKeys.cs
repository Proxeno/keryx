using System.Security.Cryptography;

namespace Keryx.Srtp;

/// <summary>
/// The master keying material for one SRTP cryptographic context direction: the master key and
/// master salt that RFC 3711 Section 4.3 key derivation expands into session keys.
/// </summary>
public sealed record SrtpSessionKeys
{
    private readonly byte[] _masterKey;
    private readonly byte[] _masterSalt;

    /// <summary>Copies <paramref name="masterKey"/> and <paramref name="masterSalt"/> into a new instance.</summary>
    /// <param name="masterKey">The master key (16 bytes for every profile defined here).</param>
    /// <param name="masterSalt">The master salt (14 bytes for AES-CM, 12 bytes for AES-GCM).</param>
    /// <exception cref="ArgumentException">Either input is empty.</exception>
    public SrtpSessionKeys(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> masterSalt)
    {
        if (masterKey.IsEmpty)
        {
            throw new ArgumentException("The SRTP master key must not be empty.", nameof(masterKey));
        }

        if (masterSalt.IsEmpty)
        {
            throw new ArgumentException("The SRTP master salt must not be empty.", nameof(masterSalt));
        }

        _masterKey = masterKey.ToArray();
        _masterSalt = masterSalt.ToArray();
    }

    /// <summary>The master key.</summary>
    public ReadOnlyMemory<byte> MasterKey => _masterKey;

    /// <summary>The master salt.</summary>
    public ReadOnlyMemory<byte> MasterSalt => _masterSalt;

    /// <summary>Compares key material in constant time.</summary>
    /// <param name="other">The instance to compare against.</param>
    public bool Equals(SrtpSessionKeys? other) =>
        other is not null
        && CryptographicOperations.FixedTimeEquals(_masterKey, other._masterKey)
        && CryptographicOperations.FixedTimeEquals(_masterSalt, other._masterSalt);

    /// <summary>Hashes only the material lengths so key bytes never leak through a hash code.</summary>
    public override int GetHashCode() => HashCode.Combine(_masterKey.Length, _masterSalt.Length);

    /// <summary>Returns a redacted description; key bytes are never rendered.</summary>
    public override string ToString() =>
        $"SrtpSessionKeys {{ MasterKey = {_masterKey.Length} bytes, MasterSalt = {_masterSalt.Length} bytes }}";
}

/// <summary>Which side of the DTLS handshake the local endpoint played (RFC 5764 Section 4.2).</summary>
public enum DtlsSrtpRole
{
    /// <summary>The local endpoint was the DTLS client, so it writes with the <c>client_write</c> keys.</summary>
    Client,

    /// <summary>The local endpoint was the DTLS server, so it writes with the <c>server_write</c> keys.</summary>
    Server,
}

/// <summary>
/// The local (outbound) and remote (inbound) master keying material produced by splitting a
/// DTLS-SRTP exporter block.
/// </summary>
/// <param name="Local">Keys used to protect packets the local endpoint sends.</param>
/// <param name="Remote">Keys used to unprotect packets the local endpoint receives.</param>
public sealed record DtlsSrtpKeyPair(SrtpSessionKeys Local, SrtpSessionKeys Remote);

/// <summary>
/// Splits the DTLS-SRTP exporter output described in RFC 5764 Section 4.2 into per-direction
/// master keys and salts.
/// </summary>
/// <remarks>
/// The exporter (label <c>"EXTRACTOR-dtls_srtp"</c>) produces
/// <c>2 * (master_key_len + master_salt_len)</c> bytes laid out as
/// <c>client_write_SRTP_master_key || server_write_SRTP_master_key ||
/// client_write_SRTP_master_salt || server_write_SRTP_master_salt</c>. For
/// <see cref="SrtpProtectionProfile.Aes128CmHmacSha1_80"/> that is 16 + 16 + 14 + 14 = 60 bytes.
/// </remarks>
public static class DtlsSrtpKeyMaterial
{
    /// <summary>Number of exporter bytes required for <paramref name="profile"/>.</summary>
    /// <param name="profile">The negotiated protection profile.</param>
    public static int RequiredLength(SrtpProtectionProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return 2 * (profile.MasterKeyLength + profile.MasterSaltLength);
    }

    /// <summary>
    /// Splits <paramref name="keyingMaterial"/> into the local and remote master key/salt pairs for
    /// an endpoint that played <paramref name="role"/> in the DTLS handshake.
    /// </summary>
    /// <param name="profile">The negotiated protection profile.</param>
    /// <param name="keyingMaterial">The exporter block; must be exactly <see cref="RequiredLength"/> bytes.</param>
    /// <param name="role">Whether the local endpoint was the DTLS client or server.</param>
    /// <exception cref="ArgumentException"><paramref name="keyingMaterial"/> has the wrong length.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="role"/> is not a defined value.</exception>
    public static DtlsSrtpKeyPair Split(
        SrtpProtectionProfile profile,
        ReadOnlySpan<byte> keyingMaterial,
        DtlsSrtpRole role)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var required = RequiredLength(profile);
        if (keyingMaterial.Length != required)
        {
            throw new ArgumentException(
                $"DTLS-SRTP keying material for {profile.Name} must be exactly {required} bytes, got {keyingMaterial.Length}.",
                nameof(keyingMaterial));
        }

        var keyLength = profile.MasterKeyLength;
        var saltLength = profile.MasterSaltLength;

        var clientKey = keyingMaterial.Slice(0, keyLength);
        var serverKey = keyingMaterial.Slice(keyLength, keyLength);
        var clientSalt = keyingMaterial.Slice(2 * keyLength, saltLength);
        var serverSalt = keyingMaterial.Slice((2 * keyLength) + saltLength, saltLength);

        var client = new SrtpSessionKeys(clientKey, clientSalt);
        var server = new SrtpSessionKeys(serverKey, serverSalt);

        return role switch
        {
            DtlsSrtpRole.Client => new DtlsSrtpKeyPair(client, server),
            DtlsSrtpRole.Server => new DtlsSrtpKeyPair(server, client),
            _ => throw new ArgumentOutOfRangeException(nameof(role), role, "Unknown DTLS-SRTP role."),
        };
    }
}
