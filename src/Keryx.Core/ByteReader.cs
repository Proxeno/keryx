using System.Buffers.Binary;

namespace Keryx.Core;

/// <summary>
/// Forward-only big-endian (network byte order) reader over a <see cref="ReadOnlySpan{T}"/>.
/// </summary>
/// <remarks>
/// All protocol layers in Keryx parse wire formats through this type so bounds checking and
/// byte-order handling live in one place. Reads past the end throw
/// <see cref="ByteBufferException"/> rather than <see cref="ArgumentOutOfRangeException"/> so
/// callers can distinguish malformed packets from programming errors.
/// </remarks>
public ref struct ByteReader
{
    private readonly ReadOnlySpan<byte> _buffer;
    private int _position;

    /// <summary>Creates a reader over <paramref name="buffer"/> starting at offset 0.</summary>
    public ByteReader(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }

    /// <summary>Current read offset from the start of the buffer.</summary>
    public readonly int Position => _position;

    /// <summary>Number of bytes not yet consumed.</summary>
    public readonly int Remaining => _buffer.Length - _position;

    /// <summary>Total length of the underlying buffer.</summary>
    public readonly int Length => _buffer.Length;

    /// <summary>Reads one byte.</summary>
    public byte ReadU8()
    {
        EnsureRemaining(1);
        return _buffer[_position++];
    }

    /// <summary>Reads a big-endian 16-bit unsigned integer.</summary>
    public ushort ReadU16()
    {
        EnsureRemaining(2);
        var value = BinaryPrimitives.ReadUInt16BigEndian(_buffer.Slice(_position, 2));
        _position += 2;
        return value;
    }

    /// <summary>Reads a big-endian 24-bit unsigned integer into the low bits of a <see cref="uint"/>.</summary>
    public uint ReadU24()
    {
        EnsureRemaining(3);
        var span = _buffer.Slice(_position, 3);
        _position += 3;
        return (uint)((span[0] << 16) | (span[1] << 8) | span[2]);
    }

    /// <summary>Reads a big-endian 32-bit unsigned integer.</summary>
    public uint ReadU32()
    {
        EnsureRemaining(4);
        var value = BinaryPrimitives.ReadUInt32BigEndian(_buffer.Slice(_position, 4));
        _position += 4;
        return value;
    }

    /// <summary>Reads a big-endian 48-bit unsigned integer into the low bits of a <see cref="ulong"/>.</summary>
    public ulong ReadU48()
    {
        EnsureRemaining(6);
        var span = _buffer.Slice(_position, 6);
        _position += 6;
        return ((ulong)span[0] << 40) | ((ulong)span[1] << 32) | ((ulong)span[2] << 24)
               | ((ulong)span[3] << 16) | ((ulong)span[4] << 8) | span[5];
    }

    /// <summary>Reads a big-endian 64-bit unsigned integer.</summary>
    public ulong ReadU64()
    {
        EnsureRemaining(8);
        var value = BinaryPrimitives.ReadUInt64BigEndian(_buffer.Slice(_position, 8));
        _position += 8;
        return value;
    }

    /// <summary>Returns a slice of <paramref name="count"/> bytes and advances past it. The slice aliases the underlying buffer.</summary>
    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        EnsureRemaining(count);
        var span = _buffer.Slice(_position, count);
        _position += count;
        return span;
    }

    /// <summary>Advances past <paramref name="count"/> bytes without reading them.</summary>
    public void Skip(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        EnsureRemaining(count);
        _position += count;
    }

    /// <summary>Returns the unread remainder without advancing. The slice aliases the underlying buffer.</summary>
    public readonly ReadOnlySpan<byte> Peek() => _buffer[_position..];

    private readonly void EnsureRemaining(int count)
    {
        if (_buffer.Length - _position < count)
        {
            throw new ByteBufferException(
                $"Attempted to read {count} byte(s) at offset {_position} but only {_buffer.Length - _position} remain.");
        }
    }
}
