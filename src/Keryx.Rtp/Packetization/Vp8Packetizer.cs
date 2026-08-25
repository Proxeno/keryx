namespace Keryx.Rtp.Packetization;

/// <summary>
/// RFC 7741 packetizer: turns one encoded VP8 frame into RTP payloads carrying the VP8 payload
/// descriptor.
/// </summary>
/// <remarks>
/// <para>
/// The input is one complete VP8 frame as the encoder emits it — the bytes of the frame's partitions
/// back to back, uncompressed data chunk (VP8 payload header) first. This packetizer does not parse
/// partition boundaries out of that stream; it treats the frame as a single logical partition and
/// fragments it purely on byte count, the same way <see cref="H264Packetizer"/> fragments a NAL unit
/// into FU-A pieces. That is a conforming RFC 7741 packetization: the start bit (S) and partition
/// index (PID) in the payload descriptor need only agree with how the sender chose to partition the
/// bitstream on the wire, and a sender is free to present the whole frame as partition 0 (RFC 7741
/// §4.2). It also matches what Keryx's H.264 packetizer does with NAL units: no bitstream-internal
/// structure is exposed to RTP beyond what the format's RTP payload spec requires.
/// </para>
/// <para>
/// When picture ID is enabled (the default), every packet of a frame carries the extended (15-bit,
/// M=1) form, matching what Chrome sends: a receiver that loses the first packet of a frame can still
/// recover the picture ID from any later packet.
/// </para>
/// <para>
/// The packetizer holds only a picture ID counter; it allocates nothing and makes a single pass over
/// the frame. The marker bit is set on the last packet of the frame (RFC 7741 §4.2 references RFC 3550
/// marker-bit semantics; RFC 7741 packetizations in the wild — including Chrome's — set it at
/// end-of-frame the same way RFC 6184 does for H.264).
/// </para>
/// </remarks>
public sealed class Vp8Packetizer : IRtpPayloadizer
{
    /// <summary>The RTP clock rate VP8 uses in WebRTC deployments (matches RFC 6386/RFC 7741 practice).</summary>
    public const uint Vp8ClockRate = 90_000;

    /// <summary>Length, in bytes, of the mandatory first octet of the payload descriptor.</summary>
    public const int MandatoryDescriptorLength = 1;

    /// <summary>Length, in bytes, of the optional extended control bits octet (the "X" byte).</summary>
    public const int ExtendedDescriptorLength = 1;

    /// <summary>Length, in bytes, of the extended (M=1, 15-bit) picture ID field.</summary>
    public const int ExtendedPictureIdLength = 2;

    /// <summary>Upper bound (exclusive) of a 15-bit picture ID before it wraps back to zero.</summary>
    public const int PictureIdModulus = 1 << 15;

    private readonly bool _includePictureId;
    private ushort _pictureId;

    /// <summary>Creates a packetizer.</summary>
    /// <param name="includePictureId">
    /// When <see langword="true"/> (the default), every packet carries the optional extended control
    /// bits octet and a 15-bit picture ID (M=1) that increments once per frame and wraps modulo
    /// <see cref="PictureIdModulus"/>. When <see langword="false"/>, only the mandatory one-byte
    /// descriptor is emitted.
    /// </param>
    public Vp8Packetizer(bool includePictureId = true)
    {
        _includePictureId = includePictureId;
    }

    /// <inheritdoc />
    public uint ClockRate => Vp8ClockRate;

    /// <summary>
    /// Always zero: like H.264, VP8's RTP payload format does not encode frame duration, so the caller
    /// must supply capture timestamps.
    /// </summary>
    /// <param name="frame">The encoded VP8 frame; ignored.</param>
    /// <returns>Zero.</returns>
    public uint GetTimestampIncrement(ReadOnlySpan<byte> frame) => 0;

    private int DescriptorLength => _includePictureId
        ? MandatoryDescriptorLength + ExtendedDescriptorLength + ExtendedPictureIdLength
        : MandatoryDescriptorLength;

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="writer"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="maxPayloadSize"/> leaves no room for the descriptor plus at least one payload byte.
    /// </exception>
    public int Packetize(ReadOnlySpan<byte> frame, uint rtpTimestamp, int maxPayloadSize, IRtpPayloadWriter writer)
    {
        // VP8's marker bit means end-of-frame, not talkspurt start, so the RTP timestamp plays no part
        // in it, exactly as for H.264.
        _ = rtpTimestamp;
        ArgumentNullException.ThrowIfNull(writer);
        var descriptorLength = DescriptorLength;
        ArgumentOutOfRangeException.ThrowIfLessThan(maxPayloadSize, descriptorLength + 1);

        if (frame.IsEmpty)
        {
            return 0;
        }

        var pictureId = _pictureId;
        _pictureId = (ushort)((_pictureId + 1) % PictureIdModulus);

        var maxFragment = maxPayloadSize - descriptorLength;
        var position = 0;
        var packets = 0;

        while (position < frame.Length)
        {
            var length = Math.Min(maxFragment, frame.Length - position);
            var isFirst = position == 0;
            var isLast = position + length == frame.Length;

            var buffer = writer.GetPayloadBuffer(length + descriptorLength);
            WriteDescriptor(buffer, isFirst, pictureId);
            frame.Slice(position, length).CopyTo(buffer[descriptorLength..]);

            position += length;
            writer.Commit(length + descriptorLength, isLast);
            packets++;
        }

        return packets;
    }

    private void WriteDescriptor(Span<byte> buffer, bool startOfFrame, ushort pictureId)
    {
        // Byte 0 (mandatory, RFC 7741 §4.2): X|R|N|S|R|PID. R bits are reserved and always zero; N
        // (non-reference frame) is left clear because the raw frame bytes alone don't say whether the
        // encoder intends this frame to be referenced later. PID (partition index) is always zero: see
        // the class remarks on why the whole frame is treated as a single partition.
        var startBit = startOfFrame ? (byte)0x10 : (byte)0x00;

        if (!_includePictureId)
        {
            buffer[0] = startBit;
            return;
        }

        buffer[0] = (byte)(0x80 | startBit); // X=1
        buffer[1] = 0x80; // I=1 (picture ID present); L, T, K clear
        buffer[2] = (byte)(0x80 | (pictureId >> 8)); // M=1, high 7 bits of the 15-bit picture ID
        buffer[3] = (byte)pictureId; // low 8 bits
    }
}
