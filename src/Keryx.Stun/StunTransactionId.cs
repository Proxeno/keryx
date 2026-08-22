using System.Buffers.Binary;
using System.Security.Cryptography;
using Keryx.Core;

namespace Keryx.Stun;

/// <summary>
/// The 96-bit transaction identifier that correlates a STUN request with its response
/// (RFC 5389 section 6).
/// </summary>
/// <remarks>
/// Stored as three big-endian 32-bit words so the type is a cheap, allocation-free dictionary key.
/// </remarks>
public readonly struct StunTransactionId : IEquatable<StunTransactionId>
{
    /// <summary>Length of a transaction identifier in bytes.</summary>
    public const int Length = 12;

    private readonly uint _w0;
    private readonly uint _w1;
    private readonly uint _w2;

    /// <summary>Creates a transaction id from exactly <see cref="Length"/> bytes in network order.</summary>
    /// <param name="bytes">The 12 identifier bytes.</param>
    /// <exception cref="ByteBufferException"><paramref name="bytes"/> is not 12 bytes long.</exception>
    public StunTransactionId(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Length)
        {
            throw new ByteBufferException($"A STUN transaction id is {Length} bytes; got {bytes.Length}.");
        }

        _w0 = BinaryPrimitives.ReadUInt32BigEndian(bytes);
        _w1 = BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]);
        _w2 = BinaryPrimitives.ReadUInt32BigEndian(bytes[8..]);
    }

    /// <summary>Generates a cryptographically random transaction id.</summary>
    public static StunTransactionId NewRandom()
    {
        Span<byte> bytes = stackalloc byte[Length];
        RandomNumberGenerator.Fill(bytes);
        return new StunTransactionId(bytes);
    }

    /// <summary>Writes the identifier into <paramref name="destination"/> in network order.</summary>
    /// <param name="destination">A span of at least <see cref="Length"/> bytes.</param>
    /// <exception cref="ByteBufferException"><paramref name="destination"/> is too short.</exception>
    public void WriteTo(Span<byte> destination)
    {
        if (destination.Length < Length)
        {
            throw new ByteBufferException($"Need {Length} bytes to write a transaction id; got {destination.Length}.");
        }

        BinaryPrimitives.WriteUInt32BigEndian(destination, _w0);
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], _w1);
        BinaryPrimitives.WriteUInt32BigEndian(destination[8..], _w2);
    }

    /// <summary>Returns the identifier as a new 12-byte array.</summary>
    public byte[] ToArray()
    {
        var bytes = new byte[Length];
        WriteTo(bytes);
        return bytes;
    }

    /// <inheritdoc />
    public bool Equals(StunTransactionId other) => _w0 == other._w0 && _w1 == other._w1 && _w2 == other._w2;

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is StunTransactionId other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(_w0, _w1, _w2);

    /// <summary>Returns the identifier as 24 lowercase hexadecimal digits.</summary>
    public override string ToString() => Convert.ToHexStringLower(ToArray());

    /// <summary>Value equality.</summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    public static bool operator ==(StunTransactionId left, StunTransactionId right) => left.Equals(right);

    /// <summary>Value inequality.</summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    public static bool operator !=(StunTransactionId left, StunTransactionId right) => !left.Equals(right);
}
