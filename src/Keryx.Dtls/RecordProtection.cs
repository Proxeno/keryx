using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Keryx.Dtls;

/// <summary>
/// AEAD record protection for one direction of a DTLS 1.2 session. Implementations wrap a single
/// BCL AEAD primitive (<see cref="AesGcm"/> or <see cref="ChaCha20Poly1305"/>) and know how to build
/// the per-record nonce and additional authenticated data for their cipher suite.
/// </summary>
internal interface IRecordProtection : IDisposable
{
    /// <summary>Number of bytes <see cref="Encrypt"/> writes for a plaintext of <paramref name="plaintextLength"/>.</summary>
    int ProtectedLength(int plaintextLength);

    /// <summary>Encrypts one record body into <paramref name="destination"/>.</summary>
    int Encrypt(
        ContentType type,
        ushort version,
        ushort epoch,
        ulong sequenceNumber,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination);

    /// <summary>
    /// Attempts to decrypt one protected record body. Returns false — never throws — when the record
    /// is too short or the tag does not verify, so the caller can discard it silently.
    /// </summary>
    bool TryDecrypt(
        ContentType type,
        ushort version,
        ushort epoch,
        ulong sequenceNumber,
        ReadOnlySpan<byte> record,
        Span<byte> destination,
        out int plaintextLength);
}

/// <summary>Builds the record-protection cipher for a negotiated cipher suite.</summary>
internal static class RecordProtection
{
    /// <summary>The largest per-record AEAD overhead of any suite Keryx implements (AES-GCM's 24 bytes).</summary>
    public const int MaxOverhead = AeadRecordCipher.Overhead;

    /// <summary>
    /// Creates the record protection for <paramref name="description"/> from a key-block-derived
    /// <paramref name="key"/> and fixed <paramref name="iv"/> (the GCM salt or the ChaCha20 write IV).
    /// </summary>
    public static IRecordProtection Create(in CipherSuiteDescription description, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) =>
        description.Aead switch
        {
            AeadAlgorithm.AesGcm => new AeadRecordCipher(key, iv),
            AeadAlgorithm.ChaCha20Poly1305 => new ChaCha20RecordCipher(key, iv),
            _ => throw new DtlsException(
                $"Unsupported AEAD algorithm {description.Aead}.",
                DtlsAlertDescription.InternalError),
        };
}

/// <summary>
/// ChaCha20-Poly1305 record protection for DTLS 1.2 (RFC 7905). Unlike AES-GCM there is no explicit
/// per-record nonce on the wire: the 12-byte nonce is the record's <c>epoch || sequence_number</c>,
/// left-padded to twelve bytes, XORed with the fixed 12-byte write IV from the key block. The only
/// record overhead is the 16-byte Poly1305 tag. The additional authenticated data is identical to the
/// AES-GCM AEAD ciphers: <c>seq_num(8) || type(1) || version(2) || plaintext_length(2)</c>, where for
/// DTLS <c>seq_num</c> is <c>epoch || sequence_number</c>.
/// </summary>
internal sealed class ChaCha20RecordCipher : IRecordProtection
{
    public const int KeyLength = 32;
    public const int IvLength = 12;
    public const int TagLength = 16;
    public const int Overhead = TagLength;
    private const int AadLength = 13;

    private readonly ChaCha20Poly1305 _chacha;
    private readonly byte[] _iv = new byte[IvLength];

    public ChaCha20RecordCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (iv.Length != IvLength)
        {
            throw new ArgumentException($"ChaCha20-Poly1305 write IV must be {IvLength} bytes.", nameof(iv));
        }

        _chacha = new ChaCha20Poly1305(key);
        iv.CopyTo(_iv);
    }

    public int ProtectedLength(int plaintextLength) => plaintextLength + Overhead;

    public int Encrypt(
        ContentType type,
        ushort version,
        ushort epoch,
        ulong sequenceNumber,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination)
    {
        var total = ProtectedLength(plaintext.Length);
        if (destination.Length < total)
        {
            throw new ArgumentException("Destination is too small for the protected record.", nameof(destination));
        }

        Span<byte> nonce = stackalloc byte[IvLength];
        BuildNonce(nonce, epoch, sequenceNumber);

        Span<byte> aad = stackalloc byte[AadLength];
        BuildAad(aad, type, version, epoch, sequenceNumber, plaintext.Length);

        var ciphertext = destination[..plaintext.Length];
        var tag = destination.Slice(plaintext.Length, TagLength);
        _chacha.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        return total;
    }

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

        Span<byte> nonce = stackalloc byte[IvLength];
        BuildNonce(nonce, epoch, sequenceNumber);

        Span<byte> aad = stackalloc byte[AadLength];
        BuildAad(aad, type, version, epoch, sequenceNumber, length);

        var ciphertext = record[..length];
        var tag = record.Slice(length, TagLength);

        try
        {
            _chacha.Decrypt(nonce, ciphertext, tag, destination[..length], aad);
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

    public void Dispose() => _chacha.Dispose();

    private void BuildNonce(Span<byte> nonce, ushort epoch, ulong sequenceNumber)
    {
        // The 8-byte record sequence (epoch || sequence_number) is left-padded to 12 bytes, then
        // XORed with the write IV (RFC 7905 §2).
        nonce[..(IvLength - 8)].Clear();
        BinaryPrimitives.WriteUInt64BigEndian(
            nonce[(IvLength - 8)..],
            ((ulong)epoch << 48) | (sequenceNumber & 0x0000_FFFF_FFFF_FFFFUL));
        for (var i = 0; i < IvLength; i++)
        {
            nonce[i] ^= _iv[i];
        }
    }

    private static void BuildAad(
        Span<byte> aad,
        ContentType type,
        ushort version,
        ushort epoch,
        ulong sequenceNumber,
        int plaintextLength)
    {
        BinaryPrimitives.WriteUInt64BigEndian(
            aad[..8],
            ((ulong)epoch << 48) | (sequenceNumber & 0x0000_FFFF_FFFF_FFFFUL));
        aad[8] = (byte)type;
        BinaryPrimitives.WriteUInt16BigEndian(aad.Slice(9, 2), version);
        BinaryPrimitives.WriteUInt16BigEndian(aad.Slice(11, 2), (ushort)plaintextLength);
    }
}
