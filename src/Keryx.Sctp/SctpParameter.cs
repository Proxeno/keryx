using Keryx.Core;

namespace Keryx.Sctp;

/// <summary>
/// A type-length-value parameter as carried inside INIT, INIT ACK and HEARTBEAT chunks
/// (RFC 9260 §3.2.1). The length field covers the four header bytes and the value but not the
/// zero padding that aligns the next parameter to a four-byte boundary.
/// </summary>
public sealed class SctpParameter
{
    /// <summary>Creates a parameter.</summary>
    /// <param name="type">Parameter type code.</param>
    /// <param name="value">Parameter value; stored by reference, not copied.</param>
    public SctpParameter(ushort type, byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Type = type;
        Value = value;
    }

    /// <summary>Creates a parameter from a well-known type code.</summary>
    /// <param name="type">Parameter type.</param>
    /// <param name="value">Parameter value; stored by reference, not copied.</param>
    public SctpParameter(SctpParameterType type, byte[] value)
        : this((ushort)type, value)
    {
    }

    /// <summary>The parameter type code.</summary>
    public ushort Type { get; }

    /// <summary>The parameter value, excluding the four-byte TLV header and any padding.</summary>
    public byte[] Value { get; }

    /// <summary>Encoded length in bytes excluding trailing padding — the value of the length field.</summary>
    public int Length => 4 + Value.Length;

    /// <summary>Encoded length rounded up to the next four-byte boundary.</summary>
    public int PaddedLength => (Length + 3) & ~3;

    /// <summary>Writes the parameter, including alignment padding, to <paramref name="writer"/>.</summary>
    /// <param name="writer">Destination writer.</param>
    public void WriteTo(ref ByteWriter writer)
    {
        writer.WriteU16(Type);
        writer.WriteU16((ushort)Length);
        writer.WriteBytes(Value);
        writer.WriteZero(PaddedLength - Length);
    }

    /// <summary>Parses a sequence of TLV parameters that fills <paramref name="body"/>.</summary>
    /// <param name="body">Buffer holding zero or more consecutive parameters.</param>
    /// <returns>The parsed parameters in wire order.</returns>
    /// <exception cref="ByteBufferException">The buffer is truncated or a length field is invalid.</exception>
    public static List<SctpParameter> ParseAll(ReadOnlySpan<byte> body)
    {
        var result = new List<SctpParameter>();
        var offset = 0;
        while (body.Length - offset >= 4)
        {
            var type = (ushort)((body[offset] << 8) | body[offset + 1]);
            var length = (ushort)((body[offset + 2] << 8) | body[offset + 3]);
            if (length < 4 || offset + length > body.Length)
            {
                throw new ByteBufferException(
                    $"Parameter 0x{type:X4} declares length {length} at offset {offset} but only {body.Length - offset} byte(s) remain.");
            }

            result.Add(new SctpParameter(type, body.Slice(offset + 4, length - 4).ToArray()));
            var padded = (length + 3) & ~3;
            offset += Math.Min(padded, body.Length - offset);
        }

        return result;
    }
}

/// <summary>
/// An error cause as carried inside ABORT and ERROR chunks (RFC 9260 §3.3.10). Structurally
/// identical to <see cref="SctpParameter"/> but drawn from a separate code registry.
/// </summary>
public sealed class SctpErrorCause
{
    /// <summary>Creates an error cause.</summary>
    /// <param name="code">Cause code.</param>
    /// <param name="value">Cause-specific information; stored by reference, not copied.</param>
    public SctpErrorCause(ushort code, byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Code = code;
        Value = value;
    }

    /// <summary>Creates an error cause from a well-known code.</summary>
    /// <param name="code">Cause code.</param>
    /// <param name="value">Cause-specific information; stored by reference, not copied.</param>
    public SctpErrorCause(SctpErrorCauseCode code, byte[] value)
        : this((ushort)code, value)
    {
    }

    /// <summary>The cause code.</summary>
    public ushort Code { get; }

    /// <summary>Cause-specific information, excluding the four-byte header and any padding.</summary>
    public byte[] Value { get; }

    /// <summary>Encoded length in bytes excluding trailing padding.</summary>
    public int Length => 4 + Value.Length;

    /// <summary>Encoded length rounded up to the next four-byte boundary.</summary>
    public int PaddedLength => (Length + 3) & ~3;

    /// <summary>Writes the cause, including alignment padding, to <paramref name="writer"/>.</summary>
    /// <param name="writer">Destination writer.</param>
    public void WriteTo(ref ByteWriter writer)
    {
        writer.WriteU16(Code);
        writer.WriteU16((ushort)Length);
        writer.WriteBytes(Value);
        writer.WriteZero(PaddedLength - Length);
    }

    /// <summary>Parses a sequence of error causes that fills <paramref name="body"/>.</summary>
    /// <param name="body">Buffer holding zero or more consecutive causes.</param>
    /// <returns>The parsed causes in wire order.</returns>
    /// <exception cref="ByteBufferException">The buffer is truncated or a length field is invalid.</exception>
    public static List<SctpErrorCause> ParseAll(ReadOnlySpan<byte> body)
    {
        var parameters = SctpParameter.ParseAll(body);
        var result = new List<SctpErrorCause>(parameters.Count);
        foreach (var parameter in parameters)
        {
            result.Add(new SctpErrorCause(parameter.Type, parameter.Value));
        }

        return result;
    }
}
