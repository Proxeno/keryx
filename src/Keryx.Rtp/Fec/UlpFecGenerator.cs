using System.Buffers.Binary;
using Keryx.Core;

namespace Keryx.Rtp.Fec;

/// <summary>
/// Accumulates a protection group of media packets and emits a single RFC 5109 level-0 ULPFEC packet
/// that lets a receiver recover any one lost packet in the group.
/// </summary>
/// <remarks>
/// <para>
/// A caller adds each outbound media packet with <see cref="TryAdd"/>; the generator folds the packet
/// into the running recovery state as it goes, so nothing is retained but the XOR accumulators. When
/// the group is as large as the caller wants — up to <see cref="UlpFecPacket.ShortMaskLength"/>
/// packets — <see cref="TryProduce"/> writes the FEC payload, and <see cref="Reset"/> starts the next
/// group. The FEC payload is the payload of an ordinary RTP packet stamped with the negotiated
/// <c>ulpfec</c> payload type, which Keryx then wraps in RED (RFC 2198) so it shares the media
/// stream's payload-type slot.
/// </para>
/// <para>
/// <b>Thread safety: single-writer.</b> Like <see cref="RtpStreamSender"/>, one generator belongs to
/// one sending path and does no locking of its own.
/// </para>
/// </remarks>
public sealed class UlpFecGenerator
{
    private readonly byte[] _payloadXor;

    private byte _firstOctetXor;
    private byte _secondOctetXor;
    private uint _timestampXor;
    private ushort _lengthXor;
    private int _protectionLength;
    private ushort _sequenceNumberBase;
    private ushort _mask;
    private int _count;
    private bool _started;

    /// <summary>Creates a generator sized for media packets whose post-header region is at most
    /// <paramref name="maxProtectedLength"/> bytes.</summary>
    /// <param name="maxProtectedLength">
    /// Largest number of octets after a media packet's fixed twelve-byte header the generator will
    /// protect. A larger packet is refused by <see cref="TryAdd"/>.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxProtectedLength"/> is not positive.</exception>
    public UlpFecGenerator(int maxProtectedLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxProtectedLength);
        _payloadXor = new byte[maxProtectedLength];
    }

    /// <summary>Number of media packets folded into the current group.</summary>
    public int Count => _count;

    /// <summary>
    /// Largest post-header region seen in the current group, and the length of the FEC payload
    /// <see cref="TryProduce"/> will write.
    /// </summary>
    public int ProtectionLength => _protectionLength;

    /// <summary>Largest FEC payload this generator can emit: the fixed headers plus its protected span.</summary>
    public int MaxFecPayloadSize => UlpFecPacket.HeaderLength + _payloadXor.Length;

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
        _mask = 0;
        _count = 0;
        _started = false;
    }

    /// <summary>Folds one media packet into the current protection group.</summary>
    /// <param name="mediaPacket">A complete media RTP packet, header included.</param>
    /// <returns>
    /// <see langword="false"/> — leaving the group unchanged — when the packet is shorter than a fixed
    /// RTP header, its sequence number falls outside the sixteen-packet window the current group's SN
    /// base opens, its slot in the group is already taken, or its post-header region is larger than the
    /// generator was sized for. Otherwise <see langword="true"/>.
    /// </returns>
    public bool TryAdd(ReadOnlySpan<byte> mediaPacket)
    {
        if (mediaPacket.Length < UlpFecPacket.FixedRtpHeaderLength)
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
            if (delta >= UlpFecPacket.ShortMaskLength)
            {
                return false;
            }
        }

        var maskBit = (ushort)(1 << (UlpFecPacket.ShortMaskLength - 1 - delta));
        if (_started && (_mask & maskBit) != 0)
        {
            return false;
        }

        var postHeader = mediaPacket[UlpFecPacket.FixedRtpHeaderLength..];
        if (postHeader.Length > _payloadXor.Length)
        {
            return false;
        }

        // From here the add commits; every mutation below is folded in with XOR so a later recovery can
        // undo the contribution of the packets it did receive (RFC 5109 §7.4.1).
        _started = true;
        _firstOctetXor ^= (byte)(mediaPacket[0] & UlpFecPacket.FirstOctetRecoveryMask);
        _secondOctetXor ^= mediaPacket[1];
        _timestampXor ^= BinaryPrimitives.ReadUInt32BigEndian(mediaPacket[4..]);
        _lengthXor ^= (ushort)postHeader.Length;
        _mask |= maskBit;
        _protectionLength = Math.Max(_protectionLength, postHeader.Length);
        for (var i = 0; i < postHeader.Length; i++)
        {
            _payloadXor[i] ^= postHeader[i];
        }

        _count++;
        return true;
    }

    /// <summary>Writes the ULPFEC payload protecting the current group.</summary>
    /// <param name="destination">Buffer receiving the FEC payload; must hold <see cref="MaxFecPayloadSize"/> bytes.</param>
    /// <param name="length">On success, the FEC payload's length in bytes.</param>
    /// <returns><see langword="false"/> when the group is empty.</returns>
    /// <exception cref="ByteBufferException">The destination cannot hold the FEC payload.</exception>
    public bool TryProduce(Span<byte> destination, out int length)
    {
        length = 0;
        if (_count == 0)
        {
            return false;
        }

        var required = UlpFecPacket.HeaderLength + _protectionLength;
        if (destination.Length < required)
        {
            throw new ByteBufferException(
                $"A ULPFEC payload of {required} byte(s) does not fit a {destination.Length}-byte destination.");
        }

        var writer = new ByteWriter(destination);
        // E = 0, L = 0 are already clear because only the low six bits are ever set on the first octet.
        writer.WriteU8(_firstOctetXor);
        writer.WriteU8(_secondOctetXor);
        writer.WriteU16(_sequenceNumberBase);
        writer.WriteU32(_timestampXor);
        writer.WriteU16(_lengthXor);
        writer.WriteU16((ushort)_protectionLength);
        writer.WriteU16(_mask);
        writer.WriteBytes(_payloadXor.AsSpan(0, _protectionLength));

        length = writer.Position;
        return true;
    }
}
