using System.Text;
using Keryx.Core;

namespace Keryx.Stun;

/// <summary>
/// ERROR-CODE: a numeric error code split into a class (hundreds digit) and a number, plus a
/// UTF-8 reason phrase (RFC 5389 section 15.6).
/// </summary>
public sealed class StunErrorCodeAttribute : StunAttribute
{
    /// <summary>400 Bad Request (RFC 5389 section 15.6).</summary>
    public const int BadRequest = 400;

    /// <summary>401 Unauthorized (RFC 5389 section 15.6).</summary>
    public const int Unauthorized = 401;

    /// <summary>420 Unknown Attribute (RFC 5389 section 15.6).</summary>
    public const int UnknownAttribute = 420;

    /// <summary>438 Stale Nonce (RFC 5389 section 15.6).</summary>
    public const int StaleNonce = 438;

    /// <summary>487 Role Conflict (RFC 8445 section 7.3.1.1).</summary>
    public const int RoleConflict = 487;

    /// <summary>500 Server Error (RFC 5389 section 15.6).</summary>
    public const int ServerError = 500;

    /// <summary>Creates the attribute.</summary>
    /// <param name="code">The error code; must be in the range 300-699.</param>
    /// <param name="reason">The reason phrase; at most 763 UTF-8 bytes.</param>
    public StunErrorCodeAttribute(int code, string reason)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(code, 300);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(code, 699);
        ArgumentNullException.ThrowIfNull(reason);

        var bytes = Encoding.UTF8.GetBytes(reason);
        if (bytes.Length > 763)
        {
            throw new ArgumentException($"An ERROR-CODE reason phrase must encode to at most 763 UTF-8 bytes; got {bytes.Length}.", nameof(reason));
        }

        Code = code;
        Reason = reason;
        _reasonUtf8 = bytes;
    }

    private readonly byte[] _reasonUtf8;

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.ErrorCode;

    /// <summary>The full error code, for example 487.</summary>
    public int Code { get; }

    /// <summary>The reason phrase.</summary>
    public string Reason { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
    {
        writer.WriteU16(0);
        writer.WriteU8((byte)(Code / 100));
        writer.WriteU8((byte)(Code % 100));
        writer.WriteBytes(_reasonUtf8);
    }

    internal static StunErrorCodeAttribute ReadValue(ReadOnlySpan<byte> value)
    {
        var reader = new ByteReader(value);
        reader.Skip(2);
        var errorClass = reader.ReadU8() & 0x07;
        var number = reader.ReadU8();
        if (errorClass < 3 || errorClass > 6 || number > 99)
        {
            throw new StunFormatException($"ERROR-CODE class {errorClass} number {number} is outside the range allowed by RFC 5389 section 15.6.");
        }

        var reason = Encoding.UTF8.GetString(reader.Peek());
        return new StunErrorCodeAttribute((errorClass * 100) + number, reason);
    }

    /// <inheritdoc />
    public override string ToString() => $"{Code} {Reason}";
}

/// <summary>
/// UNKNOWN-ATTRIBUTES: the comprehension-required attribute types a 420 responder did not
/// understand (RFC 5389 section 15.9).
/// </summary>
public sealed class StunUnknownAttributesAttribute : StunAttribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="types">The unrecognised attribute type codes.</param>
    public StunUnknownAttributesAttribute(IEnumerable<ushort> types)
    {
        ArgumentNullException.ThrowIfNull(types);
        Types = [.. types];
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.UnknownAttributes;

    /// <summary>The unrecognised attribute type codes.</summary>
    public IReadOnlyList<ushort> Types { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
    {
        foreach (var type in Types)
        {
            writer.WriteU16(type);
        }
    }

    internal static StunUnknownAttributesAttribute ReadValue(ReadOnlySpan<byte> value)
    {
        var reader = new ByteReader(value);
        var types = new List<ushort>(reader.Remaining / 2);
        while (reader.Remaining >= 2)
        {
            types.Add(reader.ReadU16());
        }

        return new StunUnknownAttributesAttribute(types);
    }
}
