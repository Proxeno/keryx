using Keryx.Core;

namespace Keryx.Sctp;

/// <summary>A HEARTBEAT or HEARTBEAT ACK chunk (RFC 9260 §3.3.5 and §3.3.6).</summary>
/// <remarks>
/// The body is a single Heartbeat Info parameter whose value is opaque to the receiver and must be
/// echoed back verbatim in the acknowledgement.
/// </remarks>
public sealed class SctpHeartbeatChunk : SctpChunk
{
    /// <summary>Creates a heartbeat chunk.</summary>
    /// <param name="type">Either <see cref="SctpChunkType.Heartbeat"/> or <see cref="SctpChunkType.HeartbeatAck"/>.</param>
    /// <param name="info">Opaque heartbeat information; stored by reference, not copied.</param>
    public SctpHeartbeatChunk(SctpChunkType type, byte[] info)
    {
        if (type is not (SctpChunkType.Heartbeat or SctpChunkType.HeartbeatAck))
        {
            throw new ArgumentOutOfRangeException(nameof(type), type, "Expected Heartbeat or HeartbeatAck.");
        }

        ArgumentNullException.ThrowIfNull(info);
        Type = type;
        Info = info;
    }

    /// <inheritdoc />
    public override SctpChunkType Type { get; }

    /// <summary>The opaque heartbeat information carried by the Heartbeat Info parameter.</summary>
    public byte[] Info { get; }

    /// <inheritdoc />
    public override int BodyLength => (4 + Info.Length + 3) & ~3;

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer)
    {
        new SctpParameter(SctpParameterType.HeartbeatInfo, Info).WriteTo(ref writer);
    }

    internal static SctpHeartbeatChunk ParseBody(SctpChunkType type, ReadOnlySpan<byte> body)
    {
        var parameters = SctpParameter.ParseAll(body);
        var info = Array.Empty<byte>();
        foreach (var parameter in parameters)
        {
            if (parameter.Type == (ushort)SctpParameterType.HeartbeatInfo)
            {
                info = parameter.Value;
                break;
            }
        }

        return new SctpHeartbeatChunk(type, info);
    }
}

/// <summary>An ABORT chunk (RFC 9260 §3.3.7).</summary>
public sealed class SctpAbortChunk : SctpChunk
{
    /// <summary>Flag bit indicating the sender filled in no verification tag of its own (T).</summary>
    public const byte TagReflectedFlag = 0x01;

    /// <inheritdoc />
    public override SctpChunkType Type => SctpChunkType.Abort;

    /// <summary>The error causes explaining the abort.</summary>
    public List<SctpErrorCause> Causes { get; } = new();

    /// <summary>Whether the T bit is set, meaning the sender reflected the received verification tag.</summary>
    public bool TagReflected
    {
        get => (Flags & TagReflectedFlag) != 0;
        set => Flags = value ? (byte)(Flags | TagReflectedFlag) : (byte)(Flags & ~TagReflectedFlag);
    }

    /// <inheritdoc />
    public override int BodyLength
    {
        get
        {
            var length = 0;
            foreach (var cause in Causes)
            {
                length += cause.PaddedLength;
            }

            return length;
        }
    }

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer)
    {
        foreach (var cause in Causes)
        {
            cause.WriteTo(ref writer);
        }
    }

    internal static SctpAbortChunk ParseBody(ReadOnlySpan<byte> body)
    {
        var chunk = new SctpAbortChunk();
        chunk.Causes.AddRange(SctpErrorCause.ParseAll(body));
        return chunk;
    }
}

/// <summary>An ERROR chunk (RFC 9260 §3.3.10).</summary>
public sealed class SctpErrorChunk : SctpChunk
{
    /// <inheritdoc />
    public override SctpChunkType Type => SctpChunkType.Error;

    /// <summary>The reported error causes.</summary>
    public List<SctpErrorCause> Causes { get; } = new();

    /// <inheritdoc />
    public override int BodyLength
    {
        get
        {
            var length = 0;
            foreach (var cause in Causes)
            {
                length += cause.PaddedLength;
            }

            return length;
        }
    }

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer)
    {
        foreach (var cause in Causes)
        {
            cause.WriteTo(ref writer);
        }
    }

    internal static SctpErrorChunk ParseBody(ReadOnlySpan<byte> body)
    {
        var chunk = new SctpErrorChunk();
        chunk.Causes.AddRange(SctpErrorCause.ParseAll(body));
        return chunk;
    }
}

/// <summary>A SHUTDOWN chunk (RFC 9260 §3.3.8).</summary>
public sealed class SctpShutdownChunk : SctpChunk
{
    /// <summary>Creates a SHUTDOWN chunk.</summary>
    /// <param name="cumulativeTsnAck">The sender's cumulative TSN ack at the time of shutdown.</param>
    public SctpShutdownChunk(uint cumulativeTsnAck) => CumulativeTsnAck = cumulativeTsnAck;

    /// <inheritdoc />
    public override SctpChunkType Type => SctpChunkType.Shutdown;

    /// <summary>The sender's cumulative TSN ack.</summary>
    public uint CumulativeTsnAck { get; set; }

    /// <inheritdoc />
    public override int BodyLength => 4;

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer) => writer.WriteU32(CumulativeTsnAck);

    internal static SctpShutdownChunk ParseBody(ReadOnlySpan<byte> body)
    {
        var reader = new ByteReader(body);
        return new SctpShutdownChunk(reader.ReadU32());
    }
}

/// <summary>A SHUTDOWN ACK chunk (RFC 9260 §3.3.9); it carries no body.</summary>
public sealed class SctpShutdownAckChunk : SctpChunk
{
    /// <inheritdoc />
    public override SctpChunkType Type => SctpChunkType.ShutdownAck;

    /// <inheritdoc />
    public override int BodyLength => 0;

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer)
    {
    }
}

/// <summary>A SHUTDOWN COMPLETE chunk (RFC 9260 §3.3.13); it carries no body.</summary>
public sealed class SctpShutdownCompleteChunk : SctpChunk
{
    /// <summary>Flag bit indicating the sender reflected the received verification tag (T).</summary>
    public const byte TagReflectedFlag = 0x01;

    /// <inheritdoc />
    public override SctpChunkType Type => SctpChunkType.ShutdownComplete;

    /// <summary>Whether the T bit is set.</summary>
    public bool TagReflected
    {
        get => (Flags & TagReflectedFlag) != 0;
        set => Flags = value ? (byte)(Flags | TagReflectedFlag) : (byte)(Flags & ~TagReflectedFlag);
    }

    /// <inheritdoc />
    public override int BodyLength => 0;

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer)
    {
    }
}

/// <summary>A COOKIE ECHO chunk (RFC 9260 §3.3.11) carrying the opaque cookie from INIT ACK.</summary>
public sealed class SctpCookieEchoChunk : SctpChunk
{
    /// <summary>Creates a COOKIE ECHO chunk.</summary>
    /// <param name="cookie">The cookie received in INIT ACK; stored by reference, not copied.</param>
    public SctpCookieEchoChunk(byte[] cookie)
    {
        ArgumentNullException.ThrowIfNull(cookie);
        Cookie = cookie;
    }

    /// <inheritdoc />
    public override SctpChunkType Type => SctpChunkType.CookieEcho;

    /// <summary>The opaque cookie.</summary>
    public byte[] Cookie { get; }

    /// <inheritdoc />
    public override int BodyLength => Cookie.Length;

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer) => writer.WriteBytes(Cookie);
}

/// <summary>A COOKIE ACK chunk (RFC 9260 §3.3.12); it carries no body.</summary>
public sealed class SctpCookieAckChunk : SctpChunk
{
    /// <inheritdoc />
    public override SctpChunkType Type => SctpChunkType.CookieAck;

    /// <inheritdoc />
    public override int BodyLength => 0;

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer)
    {
    }
}
