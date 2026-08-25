using System.Buffers.Binary;

namespace Keryx.Rtp.Fec;

/// <summary>
/// The FlexFEC (flexfec-03 / RFC 8627) FEC-repair payload format, in its flexible-mask variant
/// (R = 0, F = 0): a header carrying the XOR ("recovery") of the protected media packets' RTP header
/// fields, the SSRC of the single source stream it protects, a sequence-number base, and a
/// variable-width bitmask naming which packets in the run are protected, followed by the repair
/// payload.
/// </summary>
/// <remarks>
/// <para>
/// Unlike RFC 5109 ULPFEC — which rides the media stream's payload-type slot inside RFC 2198 RED — a
/// FlexFEC repair packet is an ordinary RTP packet on its <em>own</em> SSRC and sequence space,
/// associated with the media stream it protects through <c>a=ssrc-group:FEC-FR</c> (RFC 8627 §5.1.2).
/// The bytes modelled here are that repair packet's payload — everything after its fixed twelve-byte
/// RTP header:
/// </para>
/// <code>
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |R|F|P|X|  CC   |M| PT recovery |         length recovery       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          TS recovery                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   SSRCCount   |                    reserved                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        protected SSRC                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          SN base              |k|          Mask [0-14]        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |k|                   Mask [15-45] (optional)                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Mask [46-109] (optional)                  |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Repair Payload ...                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </code>
/// <para>
/// The two most-significant bits of the first octet are the R (retransmission) and F (fixed-block)
/// flags; Keryx writes both zero, the flexible-mask FEC variant. Below them, P, X and CC recover the
/// first RTP octet, exactly as in ULPFEC. The second octet recovers M and PT. "Length recovery" is the
/// XOR, over the group, of the octet count each media packet carries after its fixed twelve-byte
/// header (CSRC list and extensions included). <c>SSRCCount</c> is 1 — Keryx protects one source
/// stream per FlexFEC stream — and the protected SSRC names it. The mask's bit <c>j</c> (0 = most
/// significant) marks <c>SN base + j</c> as protected; the <c>k</c> continuation bit of each block
/// selects the 15-, 46- or 110-bit width. The repair payload is the XOR, over the group, of the
/// protected post-header regions.
/// </para>
/// </remarks>
public static class FlexFecPacket
{
    /// <summary>Encoding name RFC 8627 registers for the flexible FEC repair payload format.</summary>
    public const string EncodingName = "flexfec-03";

    /// <summary>The fixed portion of the FEC header before the per-source SN base: recovery fields, SSRCCount, reserved, protected SSRC.</summary>
    public const int FixedHeaderLength = 16;

    /// <summary>Offset of the per-source sequence-number base within the FEC header.</summary>
    public const int SequenceNumberBaseOffset = 16;

    /// <summary>Offset of the packet mask within the FEC header.</summary>
    public const int MaskOffset = 18;

    /// <summary>Length in bytes of the FEC header with the shortest (15-bit) mask.</summary>
    public const int MinHeaderLength = MaskOffset + ShortMaskBytes;

    /// <summary>Length in bytes of the FEC header with the widest (110-bit) mask.</summary>
    public const int MaxHeaderLength = MaskOffset + LongMaskBytes;

    /// <summary>Number of media packets the 15-bit mask spans, and the mask's byte length.</summary>
    public const int ShortMaskBits = 15;

    /// <summary>Byte length of the 15-bit mask block.</summary>
    public const int ShortMaskBytes = 2;

    /// <summary>Number of media packets the 46-bit mask spans.</summary>
    public const int MediumMaskBits = 46;

    /// <summary>Byte length of the 46-bit mask (two blocks).</summary>
    public const int MediumMaskBytes = 6;

    /// <summary>Number of media packets the 110-bit mask spans, the widest FlexFEC supports.</summary>
    public const int LongMaskBits = 110;

    /// <summary>Byte length of the 110-bit mask (three blocks).</summary>
    public const int LongMaskBytes = 14;

    /// <summary>Length in bytes of the fixed RTP header a recovered packet is rebuilt around (RFC 3550 §5.1).</summary>
    public const int FixedRtpHeaderLength = RtpHeader.FixedLength;

    // The version bits (10b) a recovered packet's first octet carries; the FEC header stores R,F in
    // their place, so recovery restores them explicitly (RFC 8627 §6.3.2).
    internal const byte RtpVersionBits = 0x80;

    // The recovery of the first RTP octet only protects P, X, CC — with the version bits (and the FEC
    // header's R, F flags) masked off.
    internal const byte FirstOctetRecoveryMask = 0x3F;

    // The R (retransmission) and F (fixed-block) flags occupy the top two bits of the first octet.
    internal const byte RetransmissionBit = 0x80;
    internal const byte FixedBlockBit = 0x40;

    // Field offsets inside the FEC header.
    private const int Byte0Offset = 0;
    private const int Byte1Offset = 1;
    private const int LengthRecoveryOffset = 2;
    private const int TsRecoveryOffset = 4;
    private const int SsrcCountOffset = 8;
    private const int ProtectedSsrcOffset = 12;

    // Continuation-bit masks for the first two mask blocks.
    private const ushort ShortContinuation = 0x8000;
    private const uint MediumContinuation = 0x8000_0000;

    /// <summary>A parsed view over a FlexFEC repair payload; every span aliases the payload it was parsed from.</summary>
    public readonly ref struct Header
    {
        internal Header(
            ReadOnlySpan<byte> payload,
            UInt128 maskBits,
            int maskBitCount,
            int maskByteLength)
        {
            IsRetransmission = (payload[Byte0Offset] & RetransmissionBit) != 0;
            IsFixedBlock = (payload[Byte0Offset] & FixedBlockBit) != 0;
            FirstOctetRecovery = (byte)(payload[Byte0Offset] & FirstOctetRecoveryMask);
            SecondOctetRecovery = payload[Byte1Offset];
            LengthRecovery = BinaryPrimitives.ReadUInt16BigEndian(payload[LengthRecoveryOffset..]);
            TimestampRecovery = BinaryPrimitives.ReadUInt32BigEndian(payload[TsRecoveryOffset..]);
            SsrcCount = payload[SsrcCountOffset];
            ProtectedSsrc = BinaryPrimitives.ReadUInt32BigEndian(payload[ProtectedSsrcOffset..]);
            SequenceNumberBase = BinaryPrimitives.ReadUInt16BigEndian(payload[SequenceNumberBaseOffset..]);
            MaskBits = maskBits;
            MaskBitCount = maskBitCount;
            FecPayload = payload[(MaskOffset + maskByteLength)..];
        }

        /// <summary>The R flag; Keryx writes it clear (a FEC repair packet, not a retransmission).</summary>
        public bool IsRetransmission { get; }

        /// <summary>The F flag; Keryx writes it clear (the flexible-mask variant, not fixed L/D blocks).</summary>
        public bool IsFixedBlock { get; }

        /// <summary>Recovery of the P, X and CC bits of the first RTP octet (the version and R/F bits masked off).</summary>
        public byte FirstOctetRecovery { get; }

        /// <summary>Recovery of the second RTP octet: the marker bit and the payload type.</summary>
        public byte SecondOctetRecovery { get; }

        /// <summary>Recovery of the "length": the octet count after each media packet's fixed header.</summary>
        public ushort LengthRecovery { get; }

        /// <summary>Recovery of the 32-bit RTP timestamp.</summary>
        public uint TimestampRecovery { get; }

        /// <summary>Number of source SSRCs protected; always 1 in a well-formed Keryx FlexFEC packet.</summary>
        public byte SsrcCount { get; }

        /// <summary>The SSRC of the single media stream this FEC packet protects.</summary>
        public uint ProtectedSsrc { get; }

        /// <summary>Sequence number of the first protected media packet the mask is measured from.</summary>
        public ushort SequenceNumberBase { get; }

        /// <summary>The packet mask, with logical bit <c>j</c> set when <c>SN base + j</c> is protected.</summary>
        public UInt128 MaskBits { get; }

        /// <summary>Width of the mask in bits: 15, 46 or 110.</summary>
        public int MaskBitCount { get; }

        /// <summary>The repair payload: the XOR of the protected post-header regions.</summary>
        public ReadOnlySpan<byte> FecPayload { get; }

        /// <summary>Whether the mask marks <paramref name="sequenceNumber"/> as protected by this FEC packet.</summary>
        /// <param name="sequenceNumber">A candidate media sequence number.</param>
        /// <returns><see langword="true"/> when the packet is within the mask width and its bit is set.</returns>
        public bool Protects(ushort sequenceNumber)
        {
            var delta = (ushort)(sequenceNumber - SequenceNumberBase);
            return delta < MaskBitCount && (MaskBits & (UInt128.One << delta)) != UInt128.Zero;
        }

        /// <summary>The number of media packets the mask marks as protected.</summary>
        public int ProtectedCount => (int)UInt128.PopCount(MaskBits);
    }

    /// <summary>Parses the FEC header from the front of a FlexFEC repair payload.</summary>
    /// <param name="fecPayload">The payload of a FlexFEC RTP packet (after its fixed twelve-byte header).</param>
    /// <param name="header">On success, the parsed header; spans alias <paramref name="fecPayload"/>.</param>
    /// <returns>
    /// <see langword="false"/> when the payload is shorter than the fixed header, does not carry exactly
    /// one protected SSRC, is not the flexible-mask variant (R = 0, F = 0), or its mask blocks run past
    /// the end of the payload.
    /// </returns>
    public static bool TryParse(ReadOnlySpan<byte> fecPayload, out Header header)
    {
        header = default;
        if (fecPayload.Length < MinHeaderLength)
        {
            return false;
        }

        // Keryx only produces and recovers the flexible-mask variant protecting a single source SSRC.
        var firstOctet = fecPayload[Byte0Offset];
        if ((firstOctet & (RetransmissionBit | FixedBlockBit)) != 0)
        {
            return false;
        }

        if (fecPayload[SsrcCountOffset] != 1)
        {
            return false;
        }

        if (!TryParseMask(fecPayload[MaskOffset..], out var maskBits, out var maskBitCount, out var maskByteLength))
        {
            return false;
        }

        header = new Header(fecPayload, maskBits, maskBitCount, maskByteLength);
        return true;
    }

    /// <summary>The sequence number the mask's <paramref name="bitIndex"/>-th slot (from the MSB) protects.</summary>
    /// <param name="sequenceNumberBase">The FEC header's SN base.</param>
    /// <param name="bitIndex">A mask bit index, 0 (most significant) to 109.</param>
    /// <returns>The protected sequence number.</returns>
    public static ushort SequenceNumberAt(ushort sequenceNumberBase, int bitIndex) =>
        (ushort)(sequenceNumberBase + bitIndex);

    /// <summary>The narrowest mask width (15, 46 or 110 bits) that spans <paramref name="maxBitIndex"/>, or -1 when none does.</summary>
    /// <param name="maxBitIndex">The highest set mask bit index, 0-based.</param>
    /// <returns>The mask bit width, or -1 when the index is beyond the widest mask.</returns>
    public static int MaskWidthFor(int maxBitIndex) => maxBitIndex switch
    {
        < ShortMaskBits => ShortMaskBits,
        < MediumMaskBits => MediumMaskBits,
        < LongMaskBits => LongMaskBits,
        _ => -1,
    };

    /// <summary>Byte length of the mask of the given bit width.</summary>
    /// <param name="maskBitCount">A mask width: 15, 46 or 110.</param>
    /// <returns>The mask's byte length: 2, 6 or 14.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maskBitCount"/> is not a valid width.</exception>
    public static int MaskByteLength(int maskBitCount) => maskBitCount switch
    {
        ShortMaskBits => ShortMaskBytes,
        MediumMaskBits => MediumMaskBytes,
        LongMaskBits => LongMaskBytes,
        _ => throw new ArgumentOutOfRangeException(nameof(maskBitCount)),
    };

    /// <summary>
    /// Serialises the packet mask into <paramref name="destination"/>, MSB-first within each block and
    /// setting the continuation bits that select the width.
    /// </summary>
    /// <param name="maskBits">Logical mask, bit <c>j</c> set when <c>SN base + j</c> is protected.</param>
    /// <param name="maskBitCount">The chosen width: 15, 46 or 110.</param>
    /// <param name="destination">Buffer receiving the mask; must hold <see cref="MaskByteLength(int)"/> bytes.</param>
    /// <returns>The number of mask bytes written.</returns>
    internal static int WriteMask(UInt128 maskBits, int maskBitCount, Span<byte> destination)
    {
        // Block 1: continuation bit + Mask[0-14], MSB-first (j = 0 is the most significant mask bit).
        ushort block1 = maskBitCount > ShortMaskBits ? ShortContinuation : (ushort)0;
        for (var j = 0; j < ShortMaskBits; j++)
        {
            if (IsSet(maskBits, j))
            {
                block1 |= (ushort)(1 << (ShortMaskBits - 1 - j));
            }
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, block1);
        if (maskBitCount == ShortMaskBits)
        {
            return ShortMaskBytes;
        }

        // Block 2: continuation bit + Mask[15-45].
        uint block2 = maskBitCount > MediumMaskBits ? MediumContinuation : 0u;
        for (var j = ShortMaskBits; j < MediumMaskBits; j++)
        {
            if (IsSet(maskBits, j))
            {
                block2 |= 1u << (MediumMaskBits - 1 - j);
            }
        }

        BinaryPrimitives.WriteUInt32BigEndian(destination[ShortMaskBytes..], block2);
        if (maskBitCount == MediumMaskBits)
        {
            return MediumMaskBytes;
        }

        // Block 3: Mask[46-109], no continuation bit (the last possible block).
        ulong block3 = 0;
        for (var j = MediumMaskBits; j < LongMaskBits; j++)
        {
            if (IsSet(maskBits, j))
            {
                block3 |= 1UL << (LongMaskBits - 1 - j);
            }
        }

        BinaryPrimitives.WriteUInt64BigEndian(destination[MediumMaskBytes..], block3);
        return LongMaskBytes;
    }

    private static bool TryParseMask(
        ReadOnlySpan<byte> mask,
        out UInt128 bits,
        out int bitCount,
        out int byteLength)
    {
        bits = UInt128.Zero;
        bitCount = 0;
        byteLength = 0;
        if (mask.Length < ShortMaskBytes)
        {
            return false;
        }

        var block1 = BinaryPrimitives.ReadUInt16BigEndian(mask);
        for (var j = 0; j < ShortMaskBits; j++)
        {
            if ((block1 & (1 << (ShortMaskBits - 1 - j))) != 0)
            {
                bits |= UInt128.One << j;
            }
        }

        if ((block1 & ShortContinuation) == 0)
        {
            bitCount = ShortMaskBits;
            byteLength = ShortMaskBytes;
            return true;
        }

        if (mask.Length < MediumMaskBytes)
        {
            return false;
        }

        var block2 = BinaryPrimitives.ReadUInt32BigEndian(mask[ShortMaskBytes..]);
        for (var j = ShortMaskBits; j < MediumMaskBits; j++)
        {
            if ((block2 & (1u << (MediumMaskBits - 1 - j))) != 0)
            {
                bits |= UInt128.One << j;
            }
        }

        if ((block2 & MediumContinuation) == 0)
        {
            bitCount = MediumMaskBits;
            byteLength = MediumMaskBytes;
            return true;
        }

        if (mask.Length < LongMaskBytes)
        {
            return false;
        }

        var block3 = BinaryPrimitives.ReadUInt64BigEndian(mask[MediumMaskBytes..]);
        for (var j = MediumMaskBits; j < LongMaskBits; j++)
        {
            if ((block3 & (1UL << (LongMaskBits - 1 - j))) != 0)
            {
                bits |= UInt128.One << j;
            }
        }

        bitCount = LongMaskBits;
        byteLength = LongMaskBytes;
        return true;
    }

    private static bool IsSet(UInt128 bits, int index) =>
        (bits & (UInt128.One << index)) != UInt128.Zero;
}
