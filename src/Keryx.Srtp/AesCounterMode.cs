using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Keryx.Srtp;

/// <summary>
/// AES in the segmented counter mode defined by RFC 3711 Section 4.1.1.
/// </summary>
/// <remarks>
/// <para>
/// A keystream segment is <c>E(k, IV) || E(k, IV + 1 mod 2^128) || E(k, IV + 2 mod 2^128) ...</c>
/// and the packet IV is
/// <c>IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)</c>
/// where <c>k_s</c> is the 112-bit session salt, <c>SSRC</c> the 32-bit synchronisation source and
/// <c>i</c> the 48-bit SRTP packet index (or the 31-bit SRTCP index).
/// </para>
/// <para>
/// The same construction is the AES-CM PRF used for key derivation (RFC 3711 Section 4.3.3), where
/// the IV is <c>x * 2^16</c>.
/// </para>
/// <para>
/// Instances are stateful (they own a reusable ECB encryptor and scratch buffers) and therefore not
/// thread-safe. After construction the transform allocates nothing: ECB has no chaining state, so
/// one encryptor is reused for every block. (<c>Aes.EncryptEcb</c>
/// would be equivalent but builds a fresh one-shot transform on every call.)
/// </para>
/// </remarks>
public sealed class AesCounterMode : IDisposable
{
    /// <summary>The AES block size in bytes; also the IV length.</summary>
    public const int BlockSize = 16;

    private const int ChunkBlocks = 64;
    private const int ChunkBytes = ChunkBlocks * BlockSize;

    private readonly Aes _aes;
    private readonly ICryptoTransform _encryptor;
    private readonly byte[] _counters = new byte[ChunkBytes];
    private readonly byte[] _blocks = new byte[ChunkBytes];
    private bool _disposed;

    /// <summary>Creates a counter-mode cipher keyed with <paramref name="key"/>.</summary>
    /// <param name="key">A 16, 24 or 32 byte AES key.</param>
    public AesCounterMode(ReadOnlySpan<byte> key)
    {
        _aes = Aes.Create();
        _aes.Mode = CipherMode.ECB;
        _aes.Padding = PaddingMode.None;
        _aes.Key = key.ToArray();
        _encryptor = _aes.CreateEncryptor();
    }

    /// <summary>
    /// XORs the keystream segment starting at <paramref name="iv"/> into <paramref name="source"/>,
    /// writing the result to <paramref name="destination"/>. Encryption and decryption are the same
    /// operation.
    /// </summary>
    /// <param name="iv">The 16-byte initial counter block.</param>
    /// <param name="source">Data to transform.</param>
    /// <param name="destination">
    /// Receives the transformed data; must be at least as long as <paramref name="source"/>. May be
    /// the same span as <paramref name="source"/> for in-place operation, but must not partially
    /// overlap it.
    /// </param>
    /// <exception cref="ArgumentException">The IV is not <see cref="BlockSize"/> bytes, or the destination is too short.</exception>
    public void Transform(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (iv.Length != BlockSize)
        {
            throw new ArgumentException($"The counter-mode IV must be {BlockSize} bytes.", nameof(iv));
        }

        if (destination.Length < source.Length)
        {
            throw new ArgumentException("The destination is shorter than the source.", nameof(destination));
        }

        Span<byte> counter = stackalloc byte[BlockSize];
        iv.CopyTo(counter);

        var offset = 0;
        while (offset < source.Length)
        {
            var chunk = Math.Min(source.Length - offset, ChunkBytes);
            var blocks = (chunk + BlockSize - 1) / BlockSize;

            for (var b = 0; b < blocks; b++)
            {
                counter.CopyTo(_counters.AsSpan(b * BlockSize, BlockSize));
                IncrementCounter(counter);
            }

            var produced = blocks * BlockSize;
            _encryptor.TransformBlock(_counters, 0, produced, _blocks, 0);

            var keystream = _blocks.AsSpan(0, chunk);
            var input = source.Slice(offset, chunk);
            var output = destination.Slice(offset, chunk);
            for (var j = 0; j < chunk; j++)
            {
                output[j] = (byte)(input[j] ^ keystream[j]);
            }

            offset += chunk;
        }
    }

    /// <summary>
    /// Writes the keystream segment starting at <paramref name="iv"/> into
    /// <paramref name="destination"/>.
    /// </summary>
    /// <param name="iv">The 16-byte initial counter block.</param>
    /// <param name="destination">Receives <c>destination.Length</c> keystream bytes.</param>
    public void GenerateKeystream(ReadOnlySpan<byte> iv, Span<byte> destination)
    {
        destination.Clear();
        Transform(iv, destination, destination);
    }

    /// <summary>
    /// Builds the RFC 3711 Section 4.1.1 packet IV
    /// <c>(sessionSalt * 2^16) XOR (ssrc * 2^64) XOR (packetIndex * 2^16)</c>.
    /// </summary>
    /// <param name="sessionSalt">The session salt (14 bytes for the AES-CM profile).</param>
    /// <param name="ssrc">The synchronisation source of the stream.</param>
    /// <param name="packetIndex">The 48-bit SRTP packet index, or the 31-bit SRTCP index.</param>
    /// <param name="destination">Receives the 16-byte IV.</param>
    /// <exception cref="ArgumentException">The destination is not <see cref="BlockSize"/> bytes, or the salt is too long.</exception>
    public static void BuildPacketIv(
        ReadOnlySpan<byte> sessionSalt,
        uint ssrc,
        ulong packetIndex,
        Span<byte> destination)
    {
        if (destination.Length != BlockSize)
        {
            throw new ArgumentException($"The IV destination must be {BlockSize} bytes.", nameof(destination));
        }

        if (sessionSalt.Length > BlockSize - 2)
        {
            throw new ArgumentException("The session salt must not exceed 14 bytes.", nameof(sessionSalt));
        }

        // k_s * 2^16: the salt occupies the most significant octets, leaving the low 16 bits
        // (octets 14 and 15) as the block counter.
        destination.Clear();
        sessionSalt.CopyTo(destination);

        // SSRC * 2^64 lands on octets 4..7.
        destination[4] ^= (byte)(ssrc >> 24);
        destination[5] ^= (byte)(ssrc >> 16);
        destination[6] ^= (byte)(ssrc >> 8);
        destination[7] ^= (byte)ssrc;

        // i * 2^16 lands on octets 8..13 (48 bits).
        destination[8] ^= (byte)(packetIndex >> 40);
        destination[9] ^= (byte)(packetIndex >> 32);
        destination[10] ^= (byte)(packetIndex >> 24);
        destination[11] ^= (byte)(packetIndex >> 16);
        destination[12] ^= (byte)(packetIndex >> 8);
        destination[13] ^= (byte)packetIndex;
    }

    /// <summary>Increments a 128-bit big-endian counter block modulo 2^128.</summary>
    private static void IncrementCounter(Span<byte> counter)
    {
        var low = BinaryPrimitives.ReadUInt64BigEndian(counter[8..]);
        low++;
        BinaryPrimitives.WriteUInt64BigEndian(counter[8..], low);
        if (low != 0)
        {
            return;
        }

        var high = BinaryPrimitives.ReadUInt64BigEndian(counter[..8]);
        BinaryPrimitives.WriteUInt64BigEndian(counter[..8], high + 1);
    }

    /// <summary>Releases the underlying AES instance and zeroes scratch buffers.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(_counters);
        CryptographicOperations.ZeroMemory(_blocks);
        _encryptor.Dispose();
        _aes.Dispose();
    }
}
