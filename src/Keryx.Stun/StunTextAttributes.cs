using System.Text;
using Keryx.Core;

namespace Keryx.Stun;

/// <summary>
/// Base class for the attributes whose value is a UTF-8 string (RFC 5389 sections 15.3, 15.7,
/// 15.8 and 15.10).
/// </summary>
public abstract class StunTextAttribute : StunAttribute
{
    private protected StunTextAttribute(string value, int maxBytes, string name)
    {
        ArgumentNullException.ThrowIfNull(value);
        var bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length > maxBytes)
        {
            throw new ArgumentException($"{name} must encode to at most {maxBytes} UTF-8 bytes; got {bytes.Length}.", nameof(value));
        }

        Value = value;
        Utf8 = bytes;
    }

    /// <summary>The decoded string value.</summary>
    public string Value { get; }

    /// <summary>The UTF-8 encoding of <see cref="Value"/>, excluding padding.</summary>
    public byte[] Utf8 { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
        => writer.WriteBytes(Utf8);

    /// <inheritdoc />
    public override string ToString() => Value;
}

/// <summary>USERNAME: the short- or long-term credential username (RFC 5389 section 15.3).</summary>
public sealed class StunUsernameAttribute : StunTextAttribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="value">The username; at most 513 UTF-8 bytes.</param>
    public StunUsernameAttribute(string value)
        : base(value, 513, "USERNAME")
    {
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.Username;
}

/// <summary>REALM: the authentication realm for long-term credentials (RFC 5389 section 15.7).</summary>
public sealed class StunRealmAttribute : StunTextAttribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="value">The realm; at most 763 UTF-8 bytes.</param>
    public StunRealmAttribute(string value)
        : base(value, 763, "REALM")
    {
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.Realm;
}

/// <summary>NONCE: the server-supplied nonce for long-term credentials (RFC 5389 section 15.8).</summary>
public sealed class StunNonceAttribute : StunTextAttribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="value">The nonce; at most 763 UTF-8 bytes.</param>
    public StunNonceAttribute(string value)
        : base(value, 763, "NONCE")
    {
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.Nonce;
}

/// <summary>SOFTWARE: a human-readable agent description (RFC 5389 section 15.10).</summary>
public sealed class StunSoftwareAttribute : StunTextAttribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="value">The software description; at most 763 UTF-8 bytes.</param>
    public StunSoftwareAttribute(string value)
        : base(value, 763, "SOFTWARE")
    {
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.Software;
}
