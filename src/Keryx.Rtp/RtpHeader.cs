using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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
/// <para>
/// Serialization and parsing both take a straight-line fast path for the common shape — no CSRC list
/// and no header extension — that moves the twelve fixed bytes as one 64-bit plus one 32-bit
/// big-endian word behind a single length check. CSRC lists and extensions run through a separate
/// cold path; the observable behaviour of the public methods is identical either way.
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

    /// <summary>
    /// True for the common header shape — no CSRC list, no header extension — which is exactly
    /// <see cref="FixedLength"/> bytes on the wire and cannot fail <see cref="Validate"/>.
    /// </summary>
    private readonly bool IsFixedOnly => CsrcData.IsEmpty && !HasExtension;

    /// <summary>The first header octet: version, P, X and CC.</summary>
    private readonly byte FirstByte => (byte)(
        FixedOnlyFirstByte
        | (HasExtension ? 0x10 : 0)
        | CsrcCount);

    /// <summary>
    /// The first header octet for a header with no CSRC list and no extension, so the X and CC fields
    /// are known to be zero and the CSRC-count division drops out.
    /// </summary>
    private readonly byte FixedOnlyFirstByte => (byte)(
        ((Version == 0 ? SupportedVersion : Version) << 6) | (HasPadding ? 0x20 : 0));

    /// <summary>The second header octet: M and PT.</summary>
    private readonly byte SecondByte => (byte)((Marker ? 0x80 : 0) | (PayloadType & 0x7F));

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
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtpHeader header)
    {
        header = default;

        if (buffer.Length < FixedLength)
        {
            return false;
        }

        // The single length check above covers both reads: bytes 0-7 carry V/P/X/CC, M/PT, the
        // sequence number and the timestamp; bytes 8-11 carry the SSRC.
        ref var start = ref MemoryMarshal.GetReference(buffer);
        var word = Unsafe.ReadUnaligned<ulong>(ref start);
        var ssrc = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref start, 8));
        if (BitConverter.IsLittleEndian)
        {
            word = BinaryPrimitives.ReverseEndianness(word);
            ssrc = BinaryPrimitives.ReverseEndianness(ssrc);
        }

        var first = (byte)(word >> 56);
        if ((first & 0xC0) != SupportedVersion << 6)
        {
            return false;
        }

        var second = (byte)(word >> 48);
        var csrcBytes = (first & 0x0F) * 4;
        var hasExtension = (first & 0x10) != 0;

        header.Version = SupportedVersion;
        header.HasPadding = (first & 0x20) != 0;
        header.HasExtension = hasExtension;
        header.Marker = (second & 0x80) != 0;
        header.PayloadType = (byte)(second & 0x7F);
        header.SequenceNumber = (ushort)(word >> 32);
        header.Timestamp = (uint)word;
        header.Ssrc = ssrc;

        if (csrcBytes == 0 && !hasExtension)
        {
            return true;
        }

        if (!TryParseTail(buffer, csrcBytes, hasExtension, out var csrcData, out var profile, out var extensionData))
        {
            header = default;
            return false;
        }

        header.CsrcData = csrcData;
        header.ExtensionProfile = profile;
        header.ExtensionData = extensionData;
        return true;
    }

    /// <summary>
    /// Parses the CSRC list and header extension that follow the fixed header. Cold path: reached only
    /// when the CC field is non-zero or the X bit is set.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool TryParseTail(
        ReadOnlySpan<byte> buffer,
        int csrcBytes,
        bool hasExtension,
        out ReadOnlySpan<byte> csrcData,
        out ushort extensionProfile,
        out ReadOnlySpan<byte> extensionData)
    {
        csrcData = default;
        extensionProfile = 0;
        extensionData = default;

        if (buffer.Length < FixedLength + csrcBytes)
        {
            return false;
        }

        csrcData = buffer.Slice(FixedLength, csrcBytes);

        if (!hasExtension)
        {
            return true;
        }

        var offset = FixedLength + csrcBytes;
        if (buffer.Length - offset < 4)
        {
            return false;
        }

        extensionProfile = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(offset, 2));
        var bodyLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(offset + 2, 2)) * 4;
        offset += 4;

        if (buffer.Length - offset < bodyLength)
        {
            return false;
        }

        extensionData = buffer.Slice(offset, bodyLength);
        return true;
    }

    /// <summary>
    /// Serializes the header into <paramref name="destination"/>.
    /// </summary>
    /// <param name="destination">Buffer of at least <see cref="HeaderLength"/> bytes.</param>
    /// <returns>The number of bytes written, equal to <see cref="HeaderLength"/>.</returns>
    /// <exception cref="ByteBufferException">The destination is too small.</exception>
    /// <exception cref="InvalidOperationException">The CSRC list or extension body has an invalid length.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public readonly int WriteTo(Span<byte> destination)
    {
        if (IsFixedOnly)
        {
            if (destination.Length < FixedLength)
            {
                ThrowDestinationTooSmall(FixedLength, destination.Length);
            }

            WriteFixed(destination, FixedOnlyFirstByte);
            return FixedLength;
        }

        return WriteToSlow(destination);
    }

    /// <summary>
    /// Serializes the header into <paramref name="destination"/> without throwing when it is too small.
    /// </summary>
    /// <param name="destination">Destination buffer.</param>
    /// <param name="bytesWritten">On success, the number of bytes written.</param>
    /// <returns><see langword="false"/> when the destination is too small.</returns>
    /// <exception cref="InvalidOperationException">The CSRC list or extension body has an invalid length.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public readonly bool TryWriteTo(Span<byte> destination, out int bytesWritten)
    {
        if (IsFixedOnly)
        {
            if (destination.Length < FixedLength)
            {
                bytesWritten = 0;
                return false;
            }

            WriteFixed(destination, FixedOnlyFirstByte);
            bytesWritten = FixedLength;
            return true;
        }

        return TryWriteToSlow(destination, out bytesWritten);
    }

    /// <summary>
    /// Writes the twelve fixed header bytes. The caller must already have checked that
    /// <paramref name="destination"/> holds at least <see cref="FixedLength"/> bytes.
    /// </summary>
    private readonly void WriteFixed(Span<byte> destination, byte firstByte)
    {
        var word = ((ulong)firstByte << 56)
            | ((ulong)SecondByte << 48)
            | ((ulong)SequenceNumber << 32)
            | Timestamp;
        var ssrc = Ssrc;
        if (BitConverter.IsLittleEndian)
        {
            word = BinaryPrimitives.ReverseEndianness(word);
            ssrc = BinaryPrimitives.ReverseEndianness(ssrc);
        }

        ref var start = ref MemoryMarshal.GetReference(destination);
        Unsafe.WriteUnaligned(ref start, word);
        Unsafe.WriteUnaligned(ref Unsafe.Add(ref start, 8), ssrc);
    }

    /// <summary>Cold serialization path: headers carrying a CSRC list or a header extension.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private readonly int WriteToSlow(Span<byte> destination)
    {
        Validate();
        var length = HeaderLength;
        if (destination.Length < length)
        {
            ThrowDestinationTooSmall(length, destination.Length);
        }

        return WriteCore(destination);
    }

    /// <summary>Cold non-throwing serialization path: headers carrying a CSRC list or a header extension.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private readonly bool TryWriteToSlow(Span<byte> destination, out int bytesWritten)
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
        WriteFixed(destination, FirstByte);
        var writer = new ByteWriter(destination[FixedLength..]);
        writer.WriteBytes(CsrcData);

        if (HasExtension)
        {
            writer.WriteU16(ExtensionProfile);
            writer.WriteU16((ushort)(ExtensionData.Length / 4));
            writer.WriteBytes(ExtensionData);
        }

        return FixedLength + writer.Position;
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

    [DoesNotReturn]
    private static void ThrowDestinationTooSmall(int required, int available) =>
        throw new ByteBufferException(
            $"RTP header needs {required} byte(s) but the destination holds {available}.");
}
