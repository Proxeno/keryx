using System.Buffers.Binary;

namespace Keryx.Core;

/// <summary>
/// Forward-only big-endian (network byte order) writer over a caller-supplied <see cref="Span{T}"/>.
/// </summary>
/// <remarks>
/// The caller owns the buffer; the writer never allocates. Writing past the end throws
/// <see cref="ByteBufferException"/>. Use <see cref="Written"/> to obtain the populated prefix.
/// </remarks>
public ref struct ByteWriter
{
    private readonly Span<byte> _buffer;
    private int _position;

    /// <summary>Creates a writer over <paramref name="buffer"/> starting at offset 0.</summary>
    public ByteWriter(Span<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }

    /// <summary>Current write offset from the start of the buffer.</summary>
    public readonly int Position => _position;

    /// <summary>Number of bytes still available.</summary>
    public readonly int Remaining => _buffer.Length - _position;

    /// <summary>The prefix of the buffer written so far.</summary>
    public readonly Span<byte> Written => _buffer[.._position];

    /// <summary>Writes one byte.</summary>
    public void WriteU8(byte value)
    {
        EnsureRemaining(1);
        _buffer[_position++] = value;
    }

    /// <summary>Writes a big-endian 16-bit unsigned integer.</summary>
    public void WriteU16(ushort value)
    {
        EnsureRemaining(2);
        BinaryPrimitives.WriteUInt16BigEndian(_buffer.Slice(_position, 2), value);
        _position += 2;
    }

    /// <summary>Writes the low 24 bits of <paramref name="value"/> as a big-endian 24-bit integer.</summary>
    public void WriteU24(uint value)
    {
        EnsureRemaining(3);
        _buffer[_position] = (byte)(value >> 16);
        _buffer[_position + 1] = (byte)(value >> 8);
        _buffer[_position + 2] = (byte)value;
        _position += 3;
    }

    /// <summary>Writes a big-endian 32-bit unsigned integer.</summary>
    public void WriteU32(uint value)
    {
        EnsureRemaining(4);
        BinaryPrimitives.WriteUInt32BigEndian(_buffer.Slice(_position, 4), value);
        _position += 4;
    }

    /// <summary>Writes the low 48 bits of <paramref name="value"/> as a big-endian 48-bit integer.</summary>
    public void WriteU48(ulong value)
    {
        EnsureRemaining(6);
        _buffer[_position] = (byte)(value >> 40);
        _buffer[_position + 1] = (byte)(value >> 32);
        _buffer[_position + 2] = (byte)(value >> 24);
        _buffer[_position + 3] = (byte)(value >> 16);
        _buffer[_position + 4] = (byte)(value >> 8);
        _buffer[_position + 5] = (byte)value;
        _position += 6;
    }

    /// <summary>Writes a big-endian 64-bit unsigned integer.</summary>
    public void WriteU64(ulong value)
    {
        EnsureRemaining(8);
        BinaryPrimitives.WriteUInt64BigEndian(_buffer.Slice(_position, 8), value);
        _position += 8;
    }

    /// <summary>Copies <paramref name="bytes"/> into the buffer.</summary>
    public void WriteBytes(ReadOnlySpan<byte> bytes)
    {
        EnsureRemaining(bytes.Length);
        bytes.CopyTo(_buffer[_position..]);
        _position += bytes.Length;
    }

    /// <summary>Writes <paramref name="count"/> zero bytes.</summary>
    public void WriteZero(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        EnsureRemaining(count);
        _buffer.Slice(_position, count).Clear();
        _position += count;
    }

    /// <summary>
    /// Reserves <paramref name="count"/> bytes and returns their offset so a caller can back-patch
    /// them later (e.g. length fields) via <see cref="Patch"/>.
    /// </summary>
    public int Reserve(int count)
    {
        var offset = _position;
        WriteZero(count);
        return offset;
    }

    /// <summary>Returns the <paramref name="count"/>-byte window at <paramref name="offset"/> for back-patching.</summary>
    public readonly Span<byte> Patch(int offset, int count)
    {
        if (offset < 0 || count < 0 || offset + count > _position)
        {
            throw new ByteBufferException(
                $"Patch window [{offset}, {offset + count}) is outside the written range [0, {_position}).");
        }

        return _buffer.Slice(offset, count);
    }

    private readonly void EnsureRemaining(int count)
    {
        if (_buffer.Length - _position < count)
        {
            throw new ByteBufferException(
                $"Attempted to write {count} byte(s) at offset {_position} but only {_buffer.Length - _position} remain.");
        }
    }
}
