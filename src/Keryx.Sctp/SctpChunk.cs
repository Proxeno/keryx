using Keryx.Core;

namespace Keryx.Sctp;

/// <summary>
/// Base class for every SCTP chunk. A chunk is a one-byte type, a one-byte flags field, a
/// two-byte length covering the header plus body, and the body itself. Chunks are padded to a
/// four-byte boundary and that padding is <em>not</em> counted by the length field
/// (RFC 9260 §3.2).
/// </summary>
public abstract class SctpChunk
{
    /// <summary>The chunk's type code.</summary>
    public abstract SctpChunkType Type { get; }

    /// <summary>The chunk's flags byte. Interpretation is chunk-specific.</summary>
    public byte Flags { get; set; }

    /// <summary>Length of the chunk body, excluding the four-byte chunk header and padding.</summary>
    public abstract int BodyLength { get; }

    /// <summary>Encoded length in bytes excluding trailing padding — the value of the length field.</summary>
    public int Length => 4 + BodyLength;

    /// <summary>Encoded length rounded up to the next four-byte boundary.</summary>
    public int PaddedLength => (Length + 3) & ~3;

    /// <summary>Writes the chunk body (everything after the four-byte chunk header).</summary>
    /// <param name="writer">Destination writer.</param>
    public abstract void WriteBody(ref ByteWriter writer);

    /// <summary>Writes the complete chunk.</summary>
    /// <param name="writer">Destination writer.</param>
    /// <param name="includePadding">
    /// When true (the default) trailing zero padding is emitted so the next chunk starts on a
    /// four-byte boundary. The final chunk of a packet may legally omit it.
    /// </param>
    public void WriteTo(ref ByteWriter writer, bool includePadding = true)
    {
        writer.WriteU8((byte)Type);
        writer.WriteU8(Flags);
        writer.WriteU16((ushort)Length);
        WriteBody(ref writer);
        if (includePadding)
        {
            writer.WriteZero(PaddedLength - Length);
        }
    }

    /// <summary>Encodes the chunk, including padding, into a new array.</summary>
    /// <returns>The encoded chunk.</returns>
    public byte[] ToArray()
    {
        var buffer = new byte[PaddedLength];
        var writer = new ByteWriter(buffer);
        WriteTo(ref writer);
        return buffer;
    }

    /// <summary>
    /// Parses one chunk given its already-decoded header fields and body. Unknown chunk types
    /// produce an <see cref="SctpUnknownChunk"/> rather than throwing, so the caller can apply the
    /// RFC 9260 §3.2 "unrecognised chunk" handling rules encoded in the type's high bits.
    /// </summary>
    /// <param name="type">Chunk type byte.</param>
    /// <param name="flags">Chunk flags byte.</param>
    /// <param name="body">Chunk body, excluding the header and any padding.</param>
    /// <returns>The parsed chunk.</returns>
    /// <exception cref="ByteBufferException">The body is truncated for the declared type.</exception>
    public static SctpChunk Parse(byte type, byte flags, ReadOnlySpan<byte> body)
    {
        SctpChunk chunk = (SctpChunkType)type switch
        {
            SctpChunkType.Data => SctpDataChunk.ParseBody(flags, body),
            SctpChunkType.Init => SctpInitChunk.ParseBody(SctpChunkType.Init, body),
            SctpChunkType.InitAck => SctpInitChunk.ParseBody(SctpChunkType.InitAck, body),
            SctpChunkType.Sack => SctpSackChunk.ParseBody(body),
            SctpChunkType.Heartbeat => SctpHeartbeatChunk.ParseBody(SctpChunkType.Heartbeat, body),
            SctpChunkType.HeartbeatAck => SctpHeartbeatChunk.ParseBody(SctpChunkType.HeartbeatAck, body),
            SctpChunkType.Abort => SctpAbortChunk.ParseBody(body),
            SctpChunkType.Shutdown => SctpShutdownChunk.ParseBody(body),
            SctpChunkType.ShutdownAck => new SctpShutdownAckChunk(),
            SctpChunkType.Error => SctpErrorChunk.ParseBody(body),
            SctpChunkType.CookieEcho => new SctpCookieEchoChunk(body.ToArray()),
            SctpChunkType.CookieAck => new SctpCookieAckChunk(),
            SctpChunkType.ShutdownComplete => new SctpShutdownCompleteChunk(),
            SctpChunkType.ForwardTsn => SctpForwardTsnChunk.ParseBody(body),
            _ => new SctpUnknownChunk(type, body.ToArray()),
        };

        chunk.Flags = flags;
        return chunk;
    }
}

/// <summary>A chunk whose type Keryx does not implement, retained verbatim so it can be reported or ignored.</summary>
public sealed class SctpUnknownChunk : SctpChunk
{
    private readonly byte _type;

    /// <summary>Creates an unknown chunk.</summary>
    /// <param name="type">The raw type byte.</param>
    /// <param name="body">The chunk body; stored by reference, not copied.</param>
    public SctpUnknownChunk(byte type, byte[] body)
    {
        ArgumentNullException.ThrowIfNull(body);
        _type = type;
        Body = body;
    }

    /// <inheritdoc />
    public override SctpChunkType Type => (SctpChunkType)_type;

    /// <summary>The raw type byte, which may not correspond to any <see cref="SctpChunkType"/> member.</summary>
    public byte RawType => _type;

    /// <summary>The undecoded chunk body.</summary>
    public byte[] Body { get; }

    /// <inheritdoc />
    public override int BodyLength => Body.Length;

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer) => writer.WriteBytes(Body);
}
