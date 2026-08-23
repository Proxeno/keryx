using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Keryx.Dtls;

/// <summary>
/// AES-GCM record protection for DTLS 1.2 (RFC 5288 §3, RFC 5246 §6.2.3.3).
/// </summary>
/// <remarks>
/// <para>
/// The AEAD nonce is <c>salt(4) || explicit_nonce(8)</c> where the salt comes from the key block's
/// <c>write_IV</c> and the explicit nonce is transmitted as the first eight bytes of the record
/// body. Keryx uses the record's <c>epoch(2) || sequence_number(6)</c> as the explicit nonce, which
/// is what every mainstream DTLS stack does and guarantees nonce uniqueness for a given key.
/// </para>
/// <para>
/// The additional authenticated data is
/// <c>seq_num(8) || type(1) || version(2) || plaintext_length(2)</c>, where for DTLS
/// <c>seq_num</c> is <c>epoch || sequence_number</c>.
/// </para>
/// <para>
/// The same construction covers both AES-128-GCM and AES-256-GCM: the two suites differ only in the
/// length of <c>key</c> (16 or 32 bytes), which <see cref="AesGcm"/> takes directly.
/// </para>
/// <para>The AES-GCM primitive itself is <see cref="AesGcm"/> from the BCL.</para>
/// </remarks>
internal sealed class AeadRecordCipher : IRecordProtection
{
    public const int SaltLength = 4;
    public const int ExplicitNonceLength = 8;
    public const int TagLength = 16;

    /// <summary>The AES-128-GCM key length; AES-256-GCM uses a 32-byte key with the same framing.</summary>
    public const int KeyLength = 16;
    public const int Overhead = ExplicitNonceLength + TagLength;
    private const int AadLength = 13;

    private readonly AesGcm _aes;
    private readonly byte[] _salt = new byte[SaltLength];

    public AeadRecordCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt)
    {
        if (salt.Length != SaltLength)
        {
            throw new ArgumentException($"AES-GCM record salt must be {SaltLength} bytes.", nameof(salt));
        }

        _aes = new AesGcm(key, TagLength);
        salt.CopyTo(_salt);
    }

    /// <summary>Number of bytes <see cref="Encrypt"/> writes for a plaintext of <paramref name="plaintextLength"/>.</summary>
    public static int CiphertextLength(int plaintextLength) => plaintextLength + Overhead;

    /// <inheritdoc />
    public int ProtectedLength(int plaintextLength) => CiphertextLength(plaintextLength);

    /// <summary>
    /// Encrypts one record body. <paramref name="destination"/> receives
    /// <c>explicit_nonce || ciphertext || tag</c>.
    /// </summary>
    public int Encrypt(
        ContentType type,
        ushort version,
        ushort epoch,
        ulong sequenceNumber,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination)
    {
        var total = CiphertextLength(plaintext.Length);
        if (destination.Length < total)
        {
            throw new ArgumentException("Destination is too small for the protected record.", nameof(destination));
        }

        Span<byte> nonce = stackalloc byte[SaltLength + ExplicitNonceLength];
        _salt.CopyTo(nonce);
        WriteSequence(nonce.Slice(SaltLength, ExplicitNonceLength), epoch, sequenceNumber);

        // The explicit nonce is transmitted in the clear ahead of the ciphertext.
        nonce.Slice(SaltLength, ExplicitNonceLength).CopyTo(destination);

        Span<byte> aad = stackalloc byte[AadLength];
        BuildAad(aad, type, version, epoch, sequenceNumber, plaintext.Length);

        var ciphertext = destination.Slice(ExplicitNonceLength, plaintext.Length);
        var tag = destination.Slice(ExplicitNonceLength + plaintext.Length, TagLength);
        _aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        return total;
    }

    /// <summary>
    /// Attempts to decrypt one protected record body. Returns false — never throws — when the
    /// record is too short or the tag does not verify, so the caller can silently discard it per
    /// RFC 6347 §4.1.2.7.
    /// </summary>
    public bool TryDecrypt(
        ContentType type,
        ushort version,
        ushort epoch,
        ulong sequenceNumber,
        ReadOnlySpan<byte> record,
        Span<byte> destination,
        out int plaintextLength)
    {
        plaintextLength = 0;
        if (record.Length < Overhead)
        {
            return false;
        }

        var length = record.Length - Overhead;
        if (destination.Length < length)
        {
            return false;
        }

        Span<byte> nonce = stackalloc byte[SaltLength + ExplicitNonceLength];
        _salt.CopyTo(nonce);
        record[..ExplicitNonceLength].CopyTo(nonce[SaltLength..]);

        Span<byte> aad = stackalloc byte[AadLength];
        BuildAad(aad, type, version, epoch, sequenceNumber, length);

        var ciphertext = record.Slice(ExplicitNonceLength, length);
        var tag = record.Slice(ExplicitNonceLength + length, TagLength);

        try
        {
            _aes.Decrypt(nonce, ciphertext, tag, destination[..length], aad);
        }
        catch (CryptographicException)
        {
            // Authentication failure: discard silently (RFC 6347 4.1.2.7).
            destination[..length].Clear();
            return false;
        }

        plaintextLength = length;
        return true;
    }

    public void Dispose() => _aes.Dispose();

    private static void WriteSequence(Span<byte> destination, ushort epoch, ulong sequenceNumber)
    {
        BinaryPrimitives.WriteUInt64BigEndian(destination, ((ulong)epoch << 48) | (sequenceNumber & 0x0000_FFFF_FFFF_FFFFUL));
    }

    private static void BuildAad(
        Span<byte> aad,
        ContentType type,
        ushort version,
        ushort epoch,
        ulong sequenceNumber,
        int plaintextLength)
    {
        WriteSequence(aad[..8], epoch, sequenceNumber);
        aad[8] = (byte)type;
        BinaryPrimitives.WriteUInt16BigEndian(aad.Slice(9, 2), version);
        BinaryPrimitives.WriteUInt16BigEndian(aad.Slice(11, 2), (ushort)plaintextLength);
    }
}
