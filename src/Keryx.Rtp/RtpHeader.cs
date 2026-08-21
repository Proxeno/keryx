using Keryx.Core;

namespace Keryx.Rtp;

/// <summary>
/// The fixed RTP header of RFC 3550 §5.1 together with its CSRC list and optional header extension
/// (RFC 3550 §5.3.1).
/// </summary>
/// <remarks>
/// <para>
/// This is a <see langword="ref struct"/> by design. The CSRC list and the header-extension body are
/// exposed as spans aliasing the caller's packet buffer instead of being copied onto the heap, so
/// parsing a received RTP packet allocates nothing at all. The scalar fields are plain values; copy
/// them out if the header information must outlive the buffer it was parsed from.
/// </para>
/// <para>
/// Parsing never throws for malformed input: <see cref="TryParse"/> returns <see langword="false"/>.
/// </para>
/// </remarks>
public ref struct RtpHeader
{
    /// <summary>The only RTP version this stack accepts (RFC 3550 §5.1).</summary>
    public const byte SupportedVersion = 2;

    /// <summary>Length in bytes of the fixed part of the header, before any CSRCs or extension.</summary>
    public const int FixedLength = 12;

    /// <summary>Maximum number of CSRC identifiers a header can carry; the CC field is four bits wide.</summary>
    public const int MaxCsrcCount = 15;

    /// <summary>RTP version number; only <see cref="SupportedVersion"/> is accepted when parsing.</summary>
    public byte Version { get; set; }

    /// <summary>The P bit: the packet carries trailing padding octets that are not part of the payload.</summary>
    public bool HasPadding { get; set; }

    /// <summary>The X bit: a header extension follows the CSRC list.</summary>
    public bool HasExtension { get; set; }

    /// <summary>The M bit; its meaning is defined by the payload-type profile.</summary>
    public bool Marker { get; set; }

    /// <summary>Seven-bit payload type identifying the format of the payload.</summary>
    public byte PayloadType { get; set; }

    /// <summary>Sequence number; increments by one per packet and wraps at 65535.</summary>
    public ushort SequenceNumber { get; set; }

    /// <summary>Sampling instant of the first octet of the payload, in payload-format clock ticks.</summary>
    public uint Timestamp { get; set; }

    /// <summary>Synchronization source identifier of the stream.</summary>
    public uint Ssrc { get; set; }

    /// <summary>
    /// The raw CSRC list: four big-endian bytes per contributing source, so its length is always a
    /// multiple of four. Empty for the common non-mixed case.
    /// </summary>
    public ReadOnlySpan<byte> CsrcData { get; set; }

    /// <summary>
    /// Profile-defined header-extension identifier, valid when <see cref="HasExtension"/> is set.
    /// See <see cref="RtpHeaderExtension.OneByteProfile"/> for the RFC 8285 one-byte form.
    /// </summary>
    public ushort ExtensionProfile { get; set; }

    /// <summary>
    /// The header-extension body, excluding the four-byte profile/length prefix. Its length is always
    /// a multiple of four. Valid when <see cref="HasExtension"/> is set.
    /// </summary>
    public ReadOnlySpan<byte> ExtensionData { get; set; }

    /// <summary>Number of contributing sources carried in <see cref="CsrcData"/>.</summary>
    public readonly int CsrcCount => CsrcData.Length / 4;

    /// <summary>Total length in bytes of the header as it appears on the wire, including CSRCs and extension.</summary>
    public readonly int HeaderLength =>
        FixedLength + CsrcData.Length + (HasExtension ? 4 + ExtensionData.Length : 0);

    /// <summary>Reads the contributing source identifier at <paramref name="index"/>.</summary>
    /// <param name="index">Zero-based index into the CSRC list.</param>
    /// <returns>The CSRC value.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The index is outside the CSRC list.</exception>
    public readonly uint GetCsrc(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, CsrcCount);
        var span = CsrcData.Slice(index * 4, 4);
        return ((uint)span[0] << 24) | ((uint)span[1] << 16) | ((uint)span[2] << 8) | span[3];
    }

    /// <summary>
    /// Enumerates the RFC 8285 one-byte-header extension elements carried by this header. The
    /// enumeration is empty unless <see cref="HasExtension"/> is set and <see cref="ExtensionProfile"/>
    /// equals <see cref="RtpHeaderExtension.OneByteProfile"/>.
    /// </summary>
    /// <returns>An allocation-free enumerator usable directly in <see langword="foreach"/>.</returns>
    public readonly RtpOneByteExtensionEnumerator GetExtensionElements() =>
        HasExtension && ExtensionProfile == RtpHeaderExtension.OneByteProfile
            ? new RtpOneByteExtensionEnumerator(ExtensionData)
            : new RtpOneByteExtensionEnumerator(default);

    /// <summary>
    /// Finds the first RFC 8285 one-byte-header extension element with the given negotiated identifier.
    /// </summary>
    /// <param name="id">The extension element identifier (1–14) negotiated via <c>a=extmap</c>.</param>
    /// <param name="data">On success, the element body.</param>
    /// <returns><see langword="true"/> when an element with that identifier is present.</returns>
    public readonly bool TryGetExtension(byte id, out ReadOnlySpan<byte> data)
    {
        foreach (var element in GetExtensionElements())
        {
            if (element.Id == id)
            {
                data = element.Data;
                return true;
            }
        }

        data = default;
        return false;
    }

    /// <summary>
    /// Parses an RTP header from the front of <paramref name="buffer"/>.
    /// </summary>
    /// <param name="buffer">A received datagram, starting at the RTP header.</param>
    /// <param name="header">On success, the parsed header; spans alias <paramref name="buffer"/>.</param>
    /// <returns>
    /// <see langword="false"/> when the buffer is shorter than the fixed header, the version is not
    /// <see cref="SupportedVersion"/>, or the CSRC list or declared extension length runs past the end
    /// of the buffer.
    /// </returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtpHeader header)
    {
        header = default;

        if (buffer.Length < FixedLength)
        {
            return false;
        }

        var first = buffer[0];
        var version = (byte)(first >> 6);
        if (version != SupportedVersion)
        {
            return false;
        }

        var csrcCount = first & 0x0F;
        var csrcBytes = csrcCount * 4;
        if (buffer.Length < FixedLength + csrcBytes)
        {
            return false;
        }

        var hasExtension = (first & 0x10) != 0;
        var second = buffer[1];

        var reader = new ByteReader(buffer);
        try
        {
            reader.Skip(2);
            header.Version = version;
            header.HasPadding = (first & 0x20) != 0;
            header.HasExtension = hasExtension;
            header.Marker = (second & 0x80) != 0;
            header.PayloadType = (byte)(second & 0x7F);
            header.SequenceNumber = reader.ReadU16();
            header.Timestamp = reader.ReadU32();
            header.Ssrc = reader.ReadU32();
            header.CsrcData = reader.ReadBytes(csrcBytes);

            if (hasExtension)
            {
                header.ExtensionProfile = reader.ReadU16();
                var wordCount = reader.ReadU16();
                header.ExtensionData = reader.ReadBytes(wordCount * 4);
            }
        }
        catch (ByteBufferException)
        {
            header = default;
            return false;
        }

        return true;
    }

    /// <summary>
    /// Serializes the header into <paramref name="destination"/>.
    /// </summary>
    /// <param name="destination">Buffer of at least <see cref="HeaderLength"/> bytes.</param>
    /// <returns>The number of bytes written, equal to <see cref="HeaderLength"/>.</returns>
    /// <exception cref="ByteBufferException">The destination is too small.</exception>
    /// <exception cref="InvalidOperationException">The CSRC list or extension body has an invalid length.</exception>
    public readonly int WriteTo(Span<byte> destination)
    {
        Validate();
        if (destination.Length < HeaderLength)
        {
            throw new ByteBufferException(
                $"RTP header needs {HeaderLength} byte(s) but the destination holds {destination.Length}.");
        }

        return WriteCore(destination);
    }

    /// <summary>
    /// Serializes the header into <paramref name="destination"/> without throwing when it is too small.
    /// </summary>
    /// <param name="destination">Destination buffer.</param>
    /// <param name="bytesWritten">On success, the number of bytes written.</param>
    /// <returns><see langword="false"/> when the destination is too small.</returns>
    /// <exception cref="InvalidOperationException">The CSRC list or extension body has an invalid length.</exception>
    public readonly bool TryWriteTo(Span<byte> destination, out int bytesWritten)
    {
        Validate();
        if (destination.Length < HeaderLength)
        {
            bytesWritten = 0;
            return false;
        }

        bytesWritten = WriteCore(destination);
        return true;
    }

    private readonly int WriteCore(Span<byte> destination)
    {
        var writer = new ByteWriter(destination);
        var version = Version == 0 ? SupportedVersion : Version;
        var first = (byte)((version << 6)
            | (HasPadding ? 0x20 : 0)
            | (HasExtension ? 0x10 : 0)
            | CsrcCount);
        writer.WriteU8(first);
        writer.WriteU8((byte)((Marker ? 0x80 : 0) | (PayloadType & 0x7F)));
        writer.WriteU16(SequenceNumber);
        writer.WriteU32(Timestamp);
        writer.WriteU32(Ssrc);
        writer.WriteBytes(CsrcData);

        if (HasExtension)
        {
            writer.WriteU16(ExtensionProfile);
            writer.WriteU16((ushort)(ExtensionData.Length / 4));
            writer.WriteBytes(ExtensionData);
        }

        return writer.Position;
    }

    private readonly void Validate()
    {
        if (CsrcData.Length % 4 != 0)
        {
            throw new InvalidOperationException("The CSRC list length must be a multiple of four bytes.");
        }

        if (CsrcCount > MaxCsrcCount)
        {
            throw new InvalidOperationException($"An RTP header carries at most {MaxCsrcCount} CSRCs.");
        }

        if (HasExtension)
        {
            if (ExtensionData.Length % 4 != 0)
            {
                throw new InvalidOperationException("The header-extension body length must be a multiple of four bytes.");
            }

            if (ExtensionData.Length / 4 > ushort.MaxValue)
            {
                throw new InvalidOperationException("The header-extension body exceeds the 16-bit word-count field.");
            }
        }
    }
}
