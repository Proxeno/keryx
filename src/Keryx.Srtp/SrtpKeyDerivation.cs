namespace Keryx.Srtp;

/// <summary>
/// The SRTP key derivation function of RFC 3711 Section 4.3, using the AES-CM PRF of
/// Section 4.3.3.
/// </summary>
/// <remarks>
/// <para>
/// With <c>r = index DIV key_derivation_rate</c>, <c>key_id = &lt;label&gt; || r</c> and
/// <c>x = key_id XOR master_salt</c> (right aligned), the derived material is
/// <c>PRF_n(k_master, x)</c>, i.e. the first <c>n</c> bytes of AES counter mode keyed with the
/// master key and started at IV <c>x * 2^16</c>.
/// </para>
/// <para>
/// RFC 3711 defines a 14-byte (112-bit) master salt. RFC 7714 Section 11 reuses this PRF for
/// AES-GCM with a 12-byte (96-bit) master salt; the shorter salt is zero-extended on the right to
/// 14 bytes before forming <c>x</c>, matching libsrtp and therefore every WebRTC deployment.
/// </para>
/// </remarks>
public static class SrtpKeyDerivation
{
    /// <summary>RFC 3711 Section 4.3.1 label for the SRTP session encryption key (<c>k_e</c>).</summary>
    public const byte SrtpEncryptionLabel = 0x00;

    /// <summary>RFC 3711 Section 4.3.1 label for the SRTP session authentication key (<c>k_a</c>).</summary>
    public const byte SrtpAuthenticationLabel = 0x01;

    /// <summary>RFC 3711 Section 4.3.1 label for the SRTP session salting key (<c>k_s</c>).</summary>
    public const byte SrtpSaltLabel = 0x02;

    /// <summary>RFC 3711 Section 4.3.2 label for the SRTCP session encryption key.</summary>
    public const byte SrtcpEncryptionLabel = 0x03;

    /// <summary>RFC 3711 Section 4.3.2 label for the SRTCP session authentication key.</summary>
    public const byte SrtcpAuthenticationLabel = 0x04;

    /// <summary>RFC 3711 Section 4.3.2 label for the SRTCP session salting key.</summary>
    public const byte SrtcpSaltLabel = 0x05;

    /// <summary>
    /// Derives <c>destination.Length</c> bytes of session key material from a master key and salt.
    /// </summary>
    /// <param name="masterKey">The master key (16, 24 or 32 bytes).</param>
    /// <param name="masterSalt">The master salt (at most 14 bytes).</param>
    /// <param name="label">One of the <c>*Label</c> constants on this type.</param>
    /// <param name="index">The packet index; the 48-bit <c>ROC || SEQ</c> for SRTP or <c>0 || SRTCP index</c> for SRTCP.</param>
    /// <param name="keyDerivationRate">The key derivation rate. Zero (the WebRTC default) means the derivation happens exactly once.</param>
    /// <param name="destination">Receives the derived material.</param>
    /// <exception cref="ArgumentException">The master salt is longer than 14 bytes.</exception>
    public static void Derive(
        ReadOnlySpan<byte> masterKey,
        ReadOnlySpan<byte> masterSalt,
        byte label,
        ulong index,
        ulong keyDerivationRate,
        Span<byte> destination)
    {
        using var prf = new AesCounterMode(masterKey);
        Derive(prf, masterSalt, label, index, keyDerivationRate, destination);
    }

    /// <summary>
    /// Derives session key material using a pre-keyed PRF, so that several labels can be derived
    /// from one master key without re-expanding the AES key schedule.
    /// </summary>
    /// <param name="prf">A counter-mode cipher keyed with the master key.</param>
    /// <param name="masterSalt">The master salt (at most 14 bytes).</param>
    /// <param name="label">One of the <c>*Label</c> constants on this type.</param>
    /// <param name="index">The packet index used to compute <c>index DIV key_derivation_rate</c>.</param>
    /// <param name="keyDerivationRate">The key derivation rate; zero means derive exactly once.</param>
    /// <param name="destination">Receives the derived material.</param>
    /// <exception cref="ArgumentNullException"><paramref name="prf"/> is null.</exception>
    /// <exception cref="ArgumentException">The master salt is longer than 14 bytes.</exception>
    public static void Derive(
        AesCounterMode prf,
        ReadOnlySpan<byte> masterSalt,
        byte label,
        ulong index,
        ulong keyDerivationRate,
        Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(prf);
        if (masterSalt.Length > AesCounterMode.BlockSize - 2)
        {
            throw new ArgumentException("The SRTP master salt must not exceed 14 bytes.", nameof(masterSalt));
        }

        // "a DIV 0 = 0 for all a" (RFC 3711 Section 4.3.1).
        var r = keyDerivationRate == 0 ? 0UL : index / keyDerivationRate;

        // x = (<label> || r) XOR master_salt, right aligned in the 14-byte salt field, then x * 2^16.
        // In the resulting 16-byte block the salt occupies octets 0..13, the label octet 7 and the
        // 48-bit r octets 8..13.
        Span<byte> iv = stackalloc byte[AesCounterMode.BlockSize];
        iv.Clear();
        masterSalt.CopyTo(iv);

        iv[7] ^= label;
        iv[8] ^= (byte)(r >> 40);
        iv[9] ^= (byte)(r >> 32);
        iv[10] ^= (byte)(r >> 24);
        iv[11] ^= (byte)(r >> 16);
        iv[12] ^= (byte)(r >> 8);
        iv[13] ^= (byte)r;

        prf.GenerateKeystream(iv, destination);
    }
}
