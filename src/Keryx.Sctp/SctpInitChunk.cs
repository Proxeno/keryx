using Keryx.Core;

namespace Keryx.Sctp;

/// <summary>
/// An INIT or INIT ACK chunk (RFC 9260 §3.3.2 and §3.3.3). The two share an identical layout;
/// only INIT ACK carries a state cookie parameter.
/// </summary>
public sealed class SctpInitChunk : SctpChunk
{
    /// <summary>Creates an INIT or INIT ACK chunk.</summary>
    /// <param name="type">Either <see cref="SctpChunkType.Init"/> or <see cref="SctpChunkType.InitAck"/>.</param>
    public SctpInitChunk(SctpChunkType type)
    {
        if (type is not (SctpChunkType.Init or SctpChunkType.InitAck))
        {
            throw new ArgumentOutOfRangeException(nameof(type), type, "Expected Init or InitAck.");
        }

        Type = type;
    }

    /// <inheritdoc />
    public override SctpChunkType Type { get; }

    /// <summary>The sender's verification tag for this association; must not be zero.</summary>
    public uint InitiateTag { get; set; }

    /// <summary>The sender's advertised receiver window, in bytes.</summary>
    public uint AdvertisedReceiverWindow { get; set; }

    /// <summary>Number of outbound streams the sender wishes to create.</summary>
    public ushort NumberOfOutboundStreams { get; set; }

    /// <summary>Maximum number of inbound streams the sender will accept.</summary>
    public ushort NumberOfInboundStreams { get; set; }

    /// <summary>The first TSN the sender will use.</summary>
    public uint InitialTsn { get; set; }

    /// <summary>Optional and variable-length parameters, in wire order.</summary>
    public List<SctpParameter> Parameters { get; } = new();

    /// <summary>The state cookie parameter value, or null when absent.</summary>
    public byte[]? StateCookie => FindParameter(SctpParameterType.StateCookie)?.Value;

    /// <summary>
    /// True when the peer advertised RFC 3758 partial reliability, either through the
    /// Forward-TSN-Supported parameter (0xC000) or by listing FORWARD TSN in Supported Extensions
    /// (0x8008). Chrome sends both.
    /// </summary>
    public bool ForwardTsnSupported =>
        FindParameter(SctpParameterType.ForwardTsnSupported) is not null || SupportsExtension(SctpChunkType.ForwardTsn);

    /// <summary>
    /// True when the peer advertised RFC 6525 stream reconfiguration by listing RE-CONFIG in the
    /// Supported Extensions parameter (0x8008).
    /// </summary>
    public bool ReconfigSupported => SupportsExtension(SctpChunkType.ReConfig);

    /// <summary>Returns whether the Supported Extensions parameter lists the given chunk type.</summary>
    /// <param name="chunkType">Chunk type to look for.</param>
    /// <returns>True when the chunk type appears in the Supported Extensions parameter.</returns>
    public bool SupportsExtension(SctpChunkType chunkType)
    {
        var extensions = FindParameter(SctpParameterType.SupportedExtensions);
        if (extensions is null)
        {
            return false;
        }

        foreach (var value in extensions.Value)
        {
            if (value == (byte)chunkType)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Returns the first parameter with the given type, or null.</summary>
    /// <param name="type">Parameter type to look for.</param>
    /// <returns>The matching parameter, or null when absent.</returns>
    public SctpParameter? FindParameter(SctpParameterType type) => FindParameter((ushort)type);

    /// <summary>Returns the first parameter with the given raw type code, or null.</summary>
    /// <param name="type">Parameter type code to look for.</param>
    /// <returns>The matching parameter, or null when absent.</returns>
    public SctpParameter? FindParameter(ushort type)
    {
        foreach (var parameter in Parameters)
        {
            if (parameter.Type == type)
            {
                return parameter;
            }
        }

        return null;
    }

    /// <inheritdoc />
    public override int BodyLength
    {
        get
        {
            var length = 16;
            foreach (var parameter in Parameters)
            {
                length += parameter.PaddedLength;
            }

            return length;
        }
    }

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer)
    {
        writer.WriteU32(InitiateTag);
        writer.WriteU32(AdvertisedReceiverWindow);
        writer.WriteU16(NumberOfOutboundStreams);
        writer.WriteU16(NumberOfInboundStreams);
        writer.WriteU32(InitialTsn);
        foreach (var parameter in Parameters)
        {
            parameter.WriteTo(ref writer);
        }
    }

    internal static SctpInitChunk ParseBody(SctpChunkType type, ReadOnlySpan<byte> body)
    {
        var reader = new ByteReader(body);
        var chunk = new SctpInitChunk(type)
        {
            InitiateTag = reader.ReadU32(),
            AdvertisedReceiverWindow = reader.ReadU32(),
            NumberOfOutboundStreams = reader.ReadU16(),
            NumberOfInboundStreams = reader.ReadU16(),
            InitialTsn = reader.ReadU32(),
        };
        chunk.Parameters.AddRange(SctpParameter.ParseAll(reader.Peek()));
        return chunk;
    }
}
