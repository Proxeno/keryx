using System.Buffers.Binary;
using Keryx.Core;

namespace Keryx.Rtp.Fec;

/// <summary>
/// Accumulates a protection group of media packets from one source stream and emits a single FlexFEC
/// (flexfec-03 / RFC 8627) repair packet payload that lets a receiver recover any one lost packet in
/// the group.
/// </summary>
/// <remarks>
/// <para>
/// A caller adds each outbound media packet with <see cref="TryAdd"/>; the generator folds the packet
/// into the running recovery state as it goes, so nothing is retained but the XOR accumulators. When
/// the group is as large as the caller wants — the flexible mask spans up to
/// <see cref="FlexFecPacket.LongMaskBits"/> sequence numbers from the base — <see cref="TryProduce"/>
/// writes the repair payload, which is the payload of an ordinary RTP packet stamped with the
/// negotiated <c>flexfec-03</c> payload type and sent on the FlexFEC stream's own SSRC and sequence
/// space (associated with the media SSRC through <c>a=ssrc-group:FEC-FR</c>). Unlike ULPFEC, no RED
/// wrapping is involved.
/// </para>
/// <para>
/// <b>Thread safety: single-writer.</b> Like <see cref="UlpFecGenerator"/>, one generator belongs to
/// one sending path and does no locking of its own.
/// </para>
/// </remarks>
public sealed class FlexFecGenerator
{
    private readonly uint _protectedSsrc;
    private readonly byte[] _payloadXor;

    private byte _firstOctetXor;
    private byte _secondOctetXor;
    private uint _timestampXor;
    private ushort _lengthXor;
    private int _protectionLength;
    private ushort _sequenceNumberBase;
    private UInt128 _mask;
    private int _maxBitIndex;
    private int _count;
    private bool _started;

    /// <summary>Creates a generator protecting the media stream identified by <paramref name="protectedSsrc"/>.</summary>
    /// <param name="protectedSsrc">SSRC of the media stream this FEC protects; stamped into every repair packet.</param>
    /// <param name="maxProtectedLength">
    /// Largest number of octets after a media packet's fixed twelve-byte header the generator will
    /// protect. A larger packet is refused by <see cref="TryAdd"/>.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxProtectedLength"/> is not positive.</exception>
    public FlexFecGenerator(uint protectedSsrc, int maxProtectedLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxProtectedLength);
        _protectedSsrc = protectedSsrc;
        _payloadXor = new byte[maxProtectedLength];
    }

    /// <summary>The SSRC of the media stream this generator protects.</summary>
    public uint ProtectedSsrc => _protectedSsrc;

    /// <summary>Number of media packets folded into the current group.</summary>
    public int Count => _count;

    /// <summary>
    /// Largest post-header region seen in the current group, and the length of the repair payload
    /// <see cref="TryProduce"/> will write.
    /// </summary>
    public int ProtectionLength => _protectionLength;

    /// <summary>Largest repair payload this generator can emit: the widest FEC header plus its protected span.</summary>
    public int MaxFecPayloadSize => FlexFecPacket.MaxHeaderLength + _payloadXor.Length;

    /// <summary>Clears the group so the generator can protect the next run of media packets.</summary>
    public void Reset()
    {
        Array.Clear(_payloadXor, 0, _protectionLength);
        _firstOctetXor = 0;
        _secondOctetXor = 0;
        _timestampXor = 0;
        _lengthXor = 0;
        _protectionLength = 0;
        _sequenceNumberBase = 0;
        _mask = UInt128.Zero;
        _maxBitIndex = 0;
        _count = 0;
        _started = false;
    }

    /// <summary>Folds one media packet into the current protection group.</summary>
    /// <param name="mediaPacket">A complete media RTP packet, header included.</param>
    /// <returns>
    /// <see langword="false"/> — leaving the group unchanged — when the packet is shorter than a fixed
    /// RTP header, its sequence number falls outside the 110-packet window the current group's SN base
    /// opens, its slot in the group is already taken, or its post-header region is larger than the
    /// generator was sized for. Otherwise <see langword="true"/>.
    /// </returns>
    public bool TryAdd(ReadOnlySpan<byte> mediaPacket)
    {
        if (mediaPacket.Length < FlexFecPacket.FixedRtpHeaderLength)
        {
            return false;
        }

        var sequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(mediaPacket[2..]);

        ushort delta;
        if (!_started)
        {
            _sequenceNumberBase = sequenceNumber;
            delta = 0;
        }
        else
        {
            delta = (ushort)(sequenceNumber - _sequenceNumberBase);
            if (delta >= FlexFecPacket.LongMaskBits)
            {
                return false;
            }
        }

        var maskBit = UInt128.One << delta;
        if (_started && (_mask & maskBit) != UInt128.Zero)
        {
            return false;
        }

        var postHeader = mediaPacket[FlexFecPacket.FixedRtpHeaderLength..];
        if (postHeader.Length > _payloadXor.Length)
        {
            return false;
        }

        // From here the add commits; every mutation below is folded in with XOR so a later recovery can
        // undo the contribution of the packets it did receive (RFC 8627 §6.3.2).
        _started = true;
        _firstOctetXor ^= (byte)(mediaPacket[0] & FlexFecPacket.FirstOctetRecoveryMask);
        _secondOctetXor ^= mediaPacket[1];
        _timestampXor ^= BinaryPrimitives.ReadUInt32BigEndian(mediaPacket[4..]);
        _lengthXor ^= (ushort)postHeader.Length;
        _mask |= maskBit;
        _maxBitIndex = Math.Max(_maxBitIndex, delta);
        _protectionLength = Math.Max(_protectionLength, postHeader.Length);
        for (var i = 0; i < postHeader.Length; i++)
        {
            _payloadXor[i] ^= postHeader[i];
        }

        _count++;
        return true;
    }

    /// <summary>Writes the FlexFEC repair payload protecting the current group.</summary>
    /// <param name="destination">Buffer receiving the repair payload; must hold <see cref="MaxFecPayloadSize"/> bytes.</param>
    /// <param name="length">On success, the repair payload's length in bytes.</param>
    /// <returns><see langword="false"/> when the group is empty.</returns>
    /// <exception cref="ByteBufferException">The destination cannot hold the repair payload.</exception>
    public bool TryProduce(Span<byte> destination, out int length)
    {
        length = 0;
        if (_count == 0)
        {
            return false;
        }

        var maskBitCount = FlexFecPacket.MaskWidthFor(_maxBitIndex);
        var maskByteLength = FlexFecPacket.MaskByteLength(maskBitCount);
        var required = FlexFecPacket.MaskOffset + maskByteLength + _protectionLength;
        if (destination.Length < required)
        {
            throw new ByteBufferException(
                $"A FlexFEC payload of {required} byte(s) does not fit a {destination.Length}-byte destination.");
        }

        var writer = new ByteWriter(destination);
        // R = 0, F = 0 are already clear because only the low six bits are ever set on the first octet.
        writer.WriteU8(_firstOctetXor);
        writer.WriteU8(_secondOctetXor);
        writer.WriteU16(_lengthXor);
        writer.WriteU32(_timestampXor);
        writer.WriteU8(1); // SSRCCount: one protected source stream.
        writer.WriteU24(0); // reserved
        writer.WriteU32(_protectedSsrc);
        writer.WriteU16(_sequenceNumberBase);

        var maskOffset = writer.Reserve(maskByteLength);
        FlexFecPacket.WriteMask(_mask, maskBitCount, writer.Patch(maskOffset, maskByteLength));
        writer.WriteBytes(_payloadXor.AsSpan(0, _protectionLength));

        length = writer.Position;
        return true;
    }
}
