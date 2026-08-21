namespace Keryx.Srtp;

/// <summary>Builds the profile-specific transform and validates master key material against it.</summary>
internal static class SrtpTransformFactory
{
    /// <summary>
    /// The WebRTC default key derivation rate. RFC 3711 Section 4.3.1: a rate of zero means the
    /// key derivation is applied exactly once, before the first packet.
    /// </summary>
    public const ulong DefaultKeyDerivationRate = 0;

    public static ISrtpTransform Create(SrtpProtectionProfile profile, SrtpSessionKeys keys)
    {
        if (keys.MasterKey.Length != profile.MasterKeyLength)
        {
            throw new ArgumentException(
                $"{profile.Name} requires a {profile.MasterKeyLength}-byte master key, got {keys.MasterKey.Length}.",
                nameof(keys));
        }

        if (keys.MasterSalt.Length != profile.MasterSaltLength)
        {
            throw new ArgumentException(
                $"{profile.Name} requires a {profile.MasterSaltLength}-byte master salt, got {keys.MasterSalt.Length}.",
                nameof(keys));
        }

        return profile.Kind switch
        {
            SrtpProtectionProfileKind.Aes128CmHmacSha1_80 =>
                new SrtpAesCmHmacSha1Transform(profile, keys, DefaultKeyDerivationRate),
            SrtpProtectionProfileKind.AeadAes128Gcm =>
                new SrtpAeadGcmTransform(profile, keys, DefaultKeyDerivationRate),
            _ => throw new ArgumentOutOfRangeException(nameof(profile), profile.Kind, "Unsupported SRTP protection profile."),
        };
    }
}
