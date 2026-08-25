using System.Buffers.Binary;
using Keryx.Core;

namespace Keryx.Rtp.Fec;

/// <summary>Counters describing one inbound stream's FlexFEC recovery.</summary>
/// <param name="MediaPacketsObserved">Media packets handed to the receiver, recovered ones excluded.</param>
/// <param name="FecPacketsObserved">FlexFEC packets handed to the receiver.</param>
/// <param name="PacketsRecovered">Media packets rebuilt from a FEC packet and its survivors.</param>
public readonly record struct FlexFecStats(long MediaPacketsObserved, long FecPacketsObserved, long PacketsRecovered);

/// <summary>
/// Recovers a single lost media packet in a FlexFEC (flexfec-03 / RFC 8627) protection group from the
/// packets that did arrive and the group's FlexFEC repair packet.
/// </summary>
/// <remarks>
/// <para>
/// The receiver mirrors <see cref="UlpFecReceiver"/>: it keeps a bounded ring of recently seen media
/// packets and a short list of FEC packets it cannot yet resolve. Each media packet (fed to
/// <see cref="OnMediaPacket"/>) and each FEC packet (fed to <see cref="OnFecPacket"/>) may complete a
/// group that was missing exactly one packet; when it does, the receiver rebuilds the missing packet
/// and queues it, so the caller drains it with <see cref="TryDequeueRecovered"/> and delivers it into
/// the same receive path a retransmission would. A group missing two or more packets is left alone —
/// the flexible-mask FEC repairs one loss per repair packet — and a packet already seen (including one
/// this receiver recovered) never triggers a second recovery, so the path cooperates with NACK/RTX and
/// the jitter buffer instead of double-delivering. A one-bit mask protecting a single packet recovers
/// that exact packet, which is how FlexFEC expresses a retransmission.
/// </para>
/// <para>
/// A FlexFEC packet names the source SSRC it protects in its header; a repair packet whose protected
/// SSRC does not match this receiver's media SSRC is declined, since its survivors live in a different
/// stream.
/// </para>
/// <para>
/// <b>Thread safety.</b> One receiver belongs to one inbound stream's receive path and does no locking
/// of its own, matching the rest of the RTP receive model.
/// </para>
/// </remarks>
public sealed class FlexFecReceiver
{
    private readonly uint _mediaSsrc;
    private readonly int _capacity;
    private readonly Dictionary<ushort, byte[]> _media = new();
    private readonly Queue<ushort> _mediaOrder = new();
    private readonly List<byte[]> _pendingFec = new();
    private readonly Queue<(ushort SequenceNumber, byte[] Packet)> _recovered = new();

    private long _mediaObserved;
    private long _fecObserved;
    private long _recoveredCount;

    /// <summary>Creates a receiver for one media stream.</summary>
    /// <param name="mediaSsrc">SSRC of the protected media stream; stamped on recovered packets and matched against each FEC packet's protected SSRC.</param>
    /// <param name="capacity">How many recent media packets to retain as recovery survivors. Must be positive.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="capacity"/> is not positive.</exception>
    public FlexFecReceiver(uint mediaSsrc, int capacity = 64)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        _mediaSsrc = mediaSsrc;
        _capacity = capacity;
    }

    /// <summary>Reads the counters.</summary>
    /// <returns>A snapshot of the receiver's counters.</returns>
    public FlexFecStats GetStats() => new(_mediaObserved, _fecObserved, _recoveredCount);

    /// <summary>Records a decoded media packet as a possible recovery survivor and marks it seen.</summary>
    /// <param name="mediaPacket">A complete media RTP packet, header included.</param>
    /// <remarks>Feeding a packet already seen (a duplicate or a recovered packet delivered back) is a no-op.</remarks>
    public void OnMediaPacket(ReadOnlySpan<byte> mediaPacket)
    {
        _mediaObserved++;
        if (mediaPacket.Length < FlexFecPacket.FixedRtpHeaderLength)
        {
            return;
        }

        var sequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(mediaPacket[2..]);
        Store(sequenceNumber, mediaPacket);
        ResolvePending();
    }

    /// <summary>Accepts a decoded FlexFEC repair payload and attempts to recover a missing packet in its group.</summary>
    /// <param name="fecPayload">The payload of a FlexFEC RTP packet (after its fixed twelve-byte header).</param>
    /// <returns><see langword="true"/> when at least one media packet was recovered and queued.</returns>
    public bool OnFecPacket(ReadOnlySpan<byte> fecPayload)
    {
        _fecObserved++;
        if (!FlexFecPacket.TryParse(fecPayload, out var header) || header.ProtectedSsrc != _mediaSsrc)
        {
            return false;
        }

        _pendingFec.Add(fecPayload.ToArray());
        var before = _recoveredCount;
        ResolvePending();
        return _recoveredCount != before;
    }

    /// <summary>Removes one recovered media packet from the queue, in recovery order.</summary>
    /// <param name="destination">Buffer receiving the recovered RTP packet.</param>
    /// <param name="length">On success, the recovered packet's length in bytes.</param>
    /// <param name="sequenceNumber">On success, the recovered packet's sequence number.</param>
    /// <returns><see langword="false"/> when no recovered packet is waiting.</returns>
    /// <exception cref="ByteBufferException">The destination cannot hold the recovered packet.</exception>
    public bool TryDequeueRecovered(Span<byte> destination, out int length, out ushort sequenceNumber)
    {
        length = 0;
        sequenceNumber = 0;
        if (_recovered.Count == 0)
        {
            return false;
        }

        var (seq, packet) = _recovered.Dequeue();
        if (destination.Length < packet.Length)
        {
            throw new ByteBufferException(
                $"A recovered packet of {packet.Length} byte(s) does not fit a {destination.Length}-byte destination.");
        }

        packet.CopyTo(destination);
        length = packet.Length;
        sequenceNumber = seq;
        return true;
    }

    private void Store(ushort sequenceNumber, ReadOnlySpan<byte> packet)
    {
        if (_media.ContainsKey(sequenceNumber))
        {
            return;
        }

        if (_mediaOrder.Count >= _capacity)
        {
            var evicted = _mediaOrder.Dequeue();
            _media.Remove(evicted);
        }

        _media[sequenceNumber] = packet.ToArray();
        _mediaOrder.Enqueue(sequenceNumber);
    }

    /// <summary>
    /// Repeatedly walks the pending FEC list, recovering any group now missing exactly one packet, until
    /// a full pass makes no progress. A recovery can complete another group, so the pass repeats.
    /// </summary>
    private void ResolvePending()
    {
        if (_pendingFec.Count == 0)
        {
            return;
        }

        bool progressed;
        do
        {
            progressed = false;
            for (var i = _pendingFec.Count - 1; i >= 0; i--)
            {
                if (TryResolveOne(_pendingFec[i]))
                {
                    _pendingFec.RemoveAt(i);
                    progressed = true;
                }
            }
        }
        while (progressed && _pendingFec.Count > 0);
    }

    private bool TryResolveOne(byte[] fecPayload)
    {
        if (!FlexFecPacket.TryParse(fecPayload, out var header) || header.ProtectedSsrc != _mediaSsrc)
        {
            // Malformed or foreign-SSRC FEC that slipped past the arrival check: discard it.
            return true;
        }

        var protectedCount = 0;
        var missingCount = 0;
        var missingSequenceNumber = (ushort)0;

        for (var bit = 0; bit < header.MaskBitCount; bit++)
        {
            var sequenceNumber = FlexFecPacket.SequenceNumberAt(header.SequenceNumberBase, bit);
            if (!header.Protects(sequenceNumber))
            {
                continue;
            }

            protectedCount++;
            if (!_media.ContainsKey(sequenceNumber))
            {
                missingCount++;
                missingSequenceNumber = sequenceNumber;
            }
        }

        if (protectedCount == 0)
        {
            return true;
        }

        // Nothing missing: the group is intact, so the FEC packet has done its job and can be dropped.
        if (missingCount == 0)
        {
            return true;
        }

        // More than one loss is beyond a single flexible-mask repair packet; keep the FEC in case a
        // survivor still arrives (a reordered packet or a retransmission) and drops the count to one.
        if (missingCount > 1)
        {
            return false;
        }

        return TryRecover(header, missingSequenceNumber);
    }

    private bool TryRecover(FlexFecPacket.Header header, ushort missingSequenceNumber)
    {
        const int fixedHeader = FlexFecPacket.FixedRtpHeaderLength;

        // First pass folds the survivors' scalar fields into the recovery fields. The length recovery
        // begins as the XOR of every protected packet's post-header length, so undoing the survivors
        // leaves the missing packet's own length — which is only known after this pass, so it sizes the
        // recovered packet below rather than the group-wide length-recovery value.
        byte firstOctet = header.FirstOctetRecovery;
        byte secondOctet = header.SecondOctetRecovery;
        var timestamp = header.TimestampRecovery;
        ushort postHeaderLength = header.LengthRecovery;

        for (var bit = 0; bit < header.MaskBitCount; bit++)
        {
            var sequenceNumber = FlexFecPacket.SequenceNumberAt(header.SequenceNumberBase, bit);
            if (!header.Protects(sequenceNumber) || sequenceNumber == missingSequenceNumber)
            {
                continue;
            }

            if (!_media.TryGetValue(sequenceNumber, out var survivor))
            {
                // A survivor left the ring before recovery could run; without it the XOR is incomplete.
                return false;
            }

            firstOctet ^= (byte)(survivor[0] & FlexFecPacket.FirstOctetRecoveryMask);
            secondOctet ^= survivor[1];
            timestamp ^= BinaryPrimitives.ReadUInt32BigEndian(survivor.AsSpan(4));
            postHeaderLength ^= (ushort)(survivor.Length - fixedHeader);
        }

        // The recovered post-header region cannot be longer than the repair payload protects; a longer
        // length means the group's protection span could not cover the missing packet.
        if (postHeaderLength > header.FecPayload.Length)
        {
            return false;
        }

        var recovered = new byte[fixedHeader + postHeaderLength];
        header.FecPayload[..postHeaderLength].CopyTo(recovered.AsSpan(fixedHeader));

        // Second pass folds the survivors' payload octets out of the repair payload, leaving the missing
        // packet's post-header bytes.
        for (var bit = 0; bit < header.MaskBitCount; bit++)
        {
            var sequenceNumber = FlexFecPacket.SequenceNumberAt(header.SequenceNumberBase, bit);
            if (!header.Protects(sequenceNumber) || sequenceNumber == missingSequenceNumber)
            {
                continue;
            }

            var survivorPost = _media[sequenceNumber].AsSpan(fixedHeader);
            var shared = Math.Min(survivorPost.Length, postHeaderLength);
            for (var i = 0; i < shared; i++)
            {
                recovered[fixedHeader + i] ^= survivorPost[i];
            }
        }

        // Restore the RTP version bits the FEC header displaced with its R/F flags, then stamp the
        // sequence number and the protected media SSRC the FEC header carried.
        recovered[0] = (byte)(FlexFecPacket.RtpVersionBits | (firstOctet & FlexFecPacket.FirstOctetRecoveryMask));
        recovered[1] = secondOctet;
        BinaryPrimitives.WriteUInt16BigEndian(recovered.AsSpan(2), missingSequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(recovered.AsSpan(4), timestamp);
        BinaryPrimitives.WriteUInt32BigEndian(recovered.AsSpan(8), _mediaSsrc);

        Store(missingSequenceNumber, recovered);
        _recovered.Enqueue((missingSequenceNumber, recovered));
        _recoveredCount++;
        return true;
    }
}
