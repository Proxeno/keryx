using Keryx.Core;

namespace Keryx.Stun;

/// <summary>
/// Base class for all STUN attributes: a type-length-value triple whose value is padded to a
/// multiple of four bytes on the wire (RFC 5389 section 15).
/// </summary>
/// <remarks>
/// The hierarchy is closed: attributes Keryx does not model are surfaced as
/// <see cref="StunRawAttribute"/>, which can also be used to emit custom attributes.
/// </remarks>
public abstract class StunAttribute
{
    private protected StunAttribute()
    {
    }

    /// <summary>The attribute's type code.</summary>
    public abstract StunAttributeType Type { get; }

    /// <summary>True when the type code is comprehension-required (below 0x8000).</summary>
    public bool IsComprehensionRequired => (ushort)Type < 0x8000;

    /// <summary>
    /// Writes the attribute's value (without the type/length header and without padding).
    /// </summary>
    /// <param name="writer">The message writer, positioned at the start of the value.</param>
    /// <param name="transactionId">
    /// The message's transaction id, needed by XOR-obfuscated attributes.
    /// </param>
    internal abstract void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId);
}

/// <summary>
/// An attribute carried as opaque bytes: either a type Keryx does not model (preserved verbatim
/// through decode/encode) or a caller-supplied extension.
/// </summary>
public sealed class StunRawAttribute : StunAttribute
{
    private readonly StunAttributeType _type;

    /// <summary>Creates a raw attribute.</summary>
    /// <param name="type">The attribute type code.</param>
    /// <param name="value">The attribute value, excluding padding. Copied.</param>
    public StunRawAttribute(StunAttributeType type, ReadOnlySpan<byte> value)
    {
        _type = type;
        Value = value.ToArray();
    }

    /// <inheritdoc />
    public override StunAttributeType Type => _type;

    /// <summary>The attribute value, excluding padding.</summary>
    public byte[] Value { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
        => writer.WriteBytes(Value);
}
