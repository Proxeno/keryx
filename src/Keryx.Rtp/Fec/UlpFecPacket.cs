using System.Buffers.Binary;

namespace Keryx.Rtp.Fec;

/// <summary>
/// The uneven level protection (ULP) FEC payload format of RFC 5109, at a single protection level
/// with the short (16-bit) packet mask — enough to protect one contiguous group of media packets and
/// recover any single loss within it.
/// </summary>
/// <remarks>
/// <para>
/// A ULPFEC packet is an ordinary RTP packet whose payload is an FEC header, one ULP level header, and
/// the level's FEC payload. The FEC header repeats the layout of an RTP header, but each field holds
/// the XOR ("recovery") of the corresponding field across every media packet the group protects, so a
/// receiver missing one packet reconstructs its fields by XORing the recovery field with the fields of
/// the packets it did receive:
/// </para>
/// <code>
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |E|L|P|X|  CC   |M| PT recovery |            SN base            |  FEC header
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          TS recovery                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        length recovery        |      protection length        |  + ULP header
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |              mask             |     FEC payload ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </code>
/// <para>
/// Keryx always writes E = 0 (no FEC-header extension) and L = 0 (16-bit mask). SN base is the
/// sequence number of the first protected media packet; the mask's bit <c>i</c> from the most
/// significant marks the packet with sequence number <c>SN base + i</c> as protected. The recovery
/// fields cover the second RTP header octet (M, PT), the timestamp, and the "length" — the octet count
/// of everything after the fixed twelve-byte header — plus the P, X and CC bits of the first octet. The
/// FEC payload is the XOR, over the group, of the first <em>protection length</em> octets that follow
/// each media packet's fixed header.
/// </para>
/// </remarks>
public static class UlpFecPacket
{
    /// <summary>Length in bytes of the FEC header (RFC 5109 §7.3): recovery fields plus the SN base.</summary>
    public const int FecHeaderLength = 10;

    /// <summary>Length in bytes of the level-0 ULP header with a short mask (RFC 5109 §7.4): protection length and mask.</summary>
    public const int UlpHeaderLength = 4;

    /// <summary>Length in bytes of the FEC and ULP headers together, before the FEC payload.</summary>
    public const int HeaderLength = FecHeaderLength + UlpHeaderLength;

    /// <summary>Number of media packets a short (16-bit) mask can span (RFC 5109 §7.4).</summary>
    public const int ShortMaskLength = 16;

    /// <summary>Length in bytes of the fixed RTP header a recovered packet is rebuilt around (RFC 3550 §5.1).</summary>
    public const int FixedRtpHeaderLength = RtpHeader.FixedLength;

    // Offsets inside the FEC payload.
    private const int Byte0Offset = 0;
    private const int Byte1Offset = 1;
    private const int SnBaseOffset = 2;
    private const int TsRecoveryOffset = 4;
    private const int LengthRecoveryOffset = 8;
    private const int ProtectionLengthOffset = 10;
    private const int MaskOffset = 12;

    // The version bits (10b) written into a recovered packet's first octet; the FEC header stores E,L
    // in their place, so recovery restores them explicitly (RFC 5109 §7.4.2).
    internal const byte RtpVersionBits = 0x80;

    // The recovery of the first RTP octet only protects P, X, CC and — with the version bits masked
    // off — leaves the E, L flags of the FEC header out of the recovered value.
    internal const byte FirstOctetRecoveryMask = 0x3F;

    /// <summary>A parsed view over a ULPFEC payload; every span aliases the payload it was parsed from.</summary>
    public readonly ref struct Header
    {
        internal Header(ReadOnlySpan<byte> payload)
        {
            FirstOctetRecovery = (byte)(payload[Byte0Offset] & FirstOctetRecoveryMask);
            SecondOctetRecovery = payload[Byte1Offset];
            SequenceNumberBase = BinaryPrimitives.ReadUInt16BigEndian(payload[SnBaseOffset..]);
            TimestampRecovery = BinaryPrimitives.ReadUInt32BigEndian(payload[TsRecoveryOffset..]);
            LengthRecovery = BinaryPrimitives.ReadUInt16BigEndian(payload[LengthRecoveryOffset..]);
            ProtectionLength = BinaryPrimitives.ReadUInt16BigEndian(payload[ProtectionLengthOffset..]);
            Mask = BinaryPrimitives.ReadUInt16BigEndian(payload[MaskOffset..]);
            FecPayload = payload.Slice(HeaderLength, ProtectionLength);
        }

        /// <summary>Recovery of the P, X and CC bits of the first RTP octet (the version bits masked off).</summary>
        public byte FirstOctetRecovery { get; }

        /// <summary>Recovery of the second RTP octet: the marker bit and the payload type.</summary>
        public byte SecondOctetRecovery { get; }

        /// <summary>Sequence number of the first protected media packet.</summary>
        public ushort SequenceNumberBase { get; }

        /// <summary>Recovery of the 32-bit RTP timestamp.</summary>
        public uint TimestampRecovery { get; }

        /// <summary>Recovery of the "length": the octet count after each media packet's fixed header.</summary>
        public ushort LengthRecovery { get; }

        /// <summary>Number of FEC payload octets, and the largest post-header region the group protects.</summary>
        public ushort ProtectionLength { get; }

        /// <summary>The short packet mask; bit <c>i</c> from the MSB marks <see cref="SequenceNumberBase"/> + i.</summary>
        public ushort Mask { get; }

        /// <summary>The level-0 FEC payload: the XOR of the protected post-header regions.</summary>
        public ReadOnlySpan<byte> FecPayload { get; }

        /// <summary>Whether the mask marks <paramref name="sequenceNumber"/> as protected by this FEC packet.</summary>
        /// <param name="sequenceNumber">A candidate media sequence number.</param>
        /// <returns><see langword="true"/> when the packet is within the mask and its bit is set.</returns>
        public bool Protects(ushort sequenceNumber)
        {
            var delta = (ushort)(sequenceNumber - SequenceNumberBase);
            return delta < ShortMaskLength && (Mask & (1 << (ShortMaskLength - 1 - delta))) != 0;
        }

        /// <summary>The number of media packets the mask marks as protected.</summary>
        public int ProtectedCount => System.Numerics.BitOperations.PopCount(Mask);
    }

    /// <summary>Parses the FEC and ULP headers from the front of a ULPFEC payload.</summary>
    /// <param name="fecPayload">The payload of a ULPFEC RTP packet.</param>
    /// <param name="header">On success, the parsed header; spans alias <paramref name="fecPayload"/>.</param>
    /// <returns>
    /// <see langword="false"/> when the payload is shorter than the fixed headers or its protection
    /// length runs past the end of the payload.
    /// </returns>
    public static bool TryParse(ReadOnlySpan<byte> fecPayload, out Header header)
    {
        header = default;
        if (fecPayload.Length < HeaderLength)
        {
            return false;
        }

        var protectionLength = BinaryPrimitives.ReadUInt16BigEndian(fecPayload[ProtectionLengthOffset..]);
        if (HeaderLength + protectionLength > fecPayload.Length)
        {
            return false;
        }

        header = new Header(fecPayload);
        return true;
    }

    /// <summary>The sequence number the mask's <paramref name="bitIndex"/>-th slot (from the MSB) protects.</summary>
    /// <param name="sequenceNumberBase">The FEC header's SN base.</param>
    /// <param name="bitIndex">A mask bit index, 0 (most significant) to 15.</param>
    /// <returns>The protected sequence number.</returns>
    public static ushort SequenceNumberAt(ushort sequenceNumberBase, int bitIndex) =>
        (ushort)(sequenceNumberBase + bitIndex);
}
