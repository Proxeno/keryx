using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Keryx.Rtp.Simulcast;

/// <summary>Inline storage for the ASCII bytes of a <see cref="SimulcastLayerId"/>.</summary>
[InlineArray(SimulcastLayerId.MaxLength)]
internal struct SimulcastLayerIdStorage
{
    private byte _element0;
}

/// <summary>
/// The identifier of one simulcast layer: the RID string (RFC 8851) carried in the RFC 8852
/// <c>rtp-stream-id</c> header extension. Stored inline as ASCII bytes so classifying a received
/// packet never allocates.
/// </summary>
/// <remarks>
/// Keryx bounds a layer identifier to <see cref="MaxLength"/> bytes: that is the largest body an
/// RFC 8285 one-byte header-extension element can carry, which is the only form
/// <see cref="RtpHeader"/> parses. A RID longer than that cannot appear on the wire Keryx reads, so
/// it is rejected rather than truncated.
/// </remarks>
public readonly struct SimulcastLayerId : IEquatable<SimulcastLayerId>
{
    /// <summary>Largest layer identifier length in bytes, matching the one-byte header-extension limit.</summary>
    public const int MaxLength = 16;

    private readonly SimulcastLayerIdStorage _storage;
    private readonly int _length;

    private SimulcastLayerId(SimulcastLayerIdStorage storage, int length)
    {
        _storage = storage;
        _length = length;
    }

    /// <summary>Length of the identifier in ASCII bytes.</summary>
    public int Length => _length;

    /// <summary>True when this is the default, unassigned identifier.</summary>
    public bool IsEmpty => _length == 0;

    /// <summary>
    /// Creates a layer identifier from the raw bytes of an <c>rtp-stream-id</c> extension element.
    /// Never throws.
    /// </summary>
    /// <param name="ascii">The extension body: 1–<see cref="MaxLength"/> printable ASCII bytes.</param>
    /// <param name="id">Receives the identifier.</param>
    /// <returns>False when the length is out of range or a byte is not printable ASCII.</returns>
    public static bool TryCreate(ReadOnlySpan<byte> ascii, out SimulcastLayerId id)
    {
        id = default;
        if (ascii.Length is 0 or > MaxLength)
        {
            return false;
        }

        foreach (var b in ascii)
        {
            // RID identifiers are alphanumeric plus '-' and '_'; require printable ASCII at minimum so
            // a stray binary body is never accepted as a layer identifier.
            if (b is < 0x21 or > 0x7E)
            {
                return false;
            }
        }

        SimulcastLayerIdStorage storage = default;
        ascii.CopyTo(MemoryMarshal.CreateSpan(ref Unsafe.As<SimulcastLayerIdStorage, byte>(ref storage), MaxLength));
        id = new SimulcastLayerId(storage, ascii.Length);
        return true;
    }

    /// <summary>Creates a layer identifier from a RID string.</summary>
    /// <param name="id">The RID identifier; must be 1–<see cref="MaxLength"/> printable ASCII characters.</param>
    /// <returns>The layer identifier.</returns>
    /// <exception cref="ArgumentException">The string is empty, too long, or not printable ASCII.</exception>
    public static SimulcastLayerId Parse(string id)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        Span<byte> ascii = stackalloc byte[MaxLength];
        if (id.Length > MaxLength)
        {
            throw new ArgumentException($"A simulcast layer identifier is at most {MaxLength} characters.", nameof(id));
        }

        for (var i = 0; i < id.Length; i++)
        {
            var c = id[i];
            if (c is < (char)0x21 or > (char)0x7E)
            {
                throw new ArgumentException("A simulcast layer identifier must be printable ASCII.", nameof(id));
            }

            ascii[i] = (byte)c;
        }

        return TryCreate(ascii[..id.Length], out var result)
            ? result
            : throw new ArgumentException("Invalid simulcast layer identifier.", nameof(id));
    }

    /// <summary>Compares this identifier's bytes against an <c>rtp-stream-id</c> extension body.</summary>
    /// <param name="ascii">The extension body to compare.</param>
    /// <returns>True when the bytes match exactly.</returns>
    public bool Matches(ReadOnlySpan<byte> ascii)
    {
        if (ascii.Length != _length)
        {
            return false;
        }

        return ascii.SequenceEqual(Bytes());
    }

    /// <summary>Copies the identifier bytes into <paramref name="destination"/>.</summary>
    /// <param name="destination">A span of at least <see cref="Length"/> bytes.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">The destination is too small.</exception>
    public int CopyTo(Span<byte> destination)
    {
        if (destination.Length < _length)
        {
            throw new ArgumentException("Destination is too small for the layer identifier.", nameof(destination));
        }

        Bytes().CopyTo(destination);
        return _length;
    }

    /// <inheritdoc/>
    public bool Equals(SimulcastLayerId other) => _length == other._length && Bytes().SequenceEqual(other.Bytes());

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is SimulcastLayerId other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Bytes());
        return hash.ToHashCode();
    }

    /// <summary>Decodes the identifier back to its RID string.</summary>
    /// <returns>The RID identifier, or the empty string when unassigned.</returns>
    public override string ToString() => _length == 0 ? string.Empty : System.Text.Encoding.ASCII.GetString(Bytes());

    /// <summary>Equality operator.</summary>
    public static bool operator ==(SimulcastLayerId left, SimulcastLayerId right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(SimulcastLayerId left, SimulcastLayerId right) => !left.Equals(right);

    private ReadOnlySpan<byte> Bytes() =>
        MemoryMarshal.CreateReadOnlySpan(
            ref Unsafe.As<SimulcastLayerIdStorage, byte>(ref Unsafe.AsRef(in _storage)),
            _length);
}
