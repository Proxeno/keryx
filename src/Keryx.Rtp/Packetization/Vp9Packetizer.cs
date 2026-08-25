namespace Keryx.Rtp.Packetization;

/// <summary>
/// draft-ietf-payload-vp9 packetizer: turns one encoded VP9 frame into RTP payloads carrying the VP9
/// payload descriptor.
/// </summary>
/// <remarks>
/// <para>
/// The input is one complete VP9 frame as the encoder emits it. Like <see cref="Vp8Packetizer"/>, this
/// packetizer does not expose the frame's internal partitioning to RTP: it fragments the frame purely
/// on byte count, setting the B (start of frame) bit on the first packet and the E (end of frame) bit
/// on the last, and the marker bit on the last packet of the frame (the frame is the whole temporal
/// unit here — no spatial-layer aggregation). That is a conforming non-flexible-mode packetization.
/// </para>
/// <para>
/// The one field the packetizer reads out of the bitstream is the frame type: it parses the VP9
/// uncompressed header (draft-ietf-payload-vp9 §4.1, VP9 bitstream §6.2) far enough to learn whether
/// the frame is a key frame, and stamps the descriptor's P (inter-picture predicted) bit accordingly —
/// P=0 for a key frame, P=1 for an inter frame — so a receiver can detect the key frame from the
/// descriptor alone, exactly as libwebrtc does.
/// </para>
/// <para>
/// When picture ID is enabled (the default), every packet carries the extended (15-bit, M=1) picture
/// ID, matching what Chrome sends, so a receiver that loses the first packet of a frame can still
/// recover the picture ID from any later packet. Layer indices (L), flexible mode (F) and the
/// scalability structure (V) are never emitted — this is a single-layer, non-flexible packetization;
/// <see cref="Vp9Depacketizer"/> parses and skips those fields when a remote peer sends them.
/// </para>
/// <para>
/// The packetizer holds only a picture ID counter; it allocates nothing and makes a single pass over
/// the frame.
/// </para>
/// </remarks>
public sealed class Vp9Packetizer : IRtpPayloadizer
{
    /// <summary>The RTP clock rate VP9 uses in WebRTC deployments.</summary>
    public const uint Vp9ClockRate = 90_000;

    /// <summary>Length, in bytes, of the mandatory first octet of the payload descriptor.</summary>
    public const int MandatoryDescriptorLength = 1;

    /// <summary>Length, in bytes, of the extended (M=1, 15-bit) picture ID field.</summary>
    public const int ExtendedPictureIdLength = 2;

    /// <summary>Upper bound (exclusive) of a 15-bit picture ID before it wraps back to zero.</summary>
    public const int PictureIdModulus = 1 << 15;

    // Descriptor byte 0 bit masks (draft-ietf-payload-vp9 §4.2): I|P|L|F|B|E|V|Z.
    private const byte PictureIdPresent = 0x80; // I
    private const byte InterPicturePredicted = 0x40; // P
    private const byte StartOfFrame = 0x08; // B
    private const byte EndOfFrame = 0x04; // E

    private readonly bool _includePictureId;
    private ushort _pictureId;

    /// <summary>Creates a packetizer.</summary>
    /// <param name="includePictureId">
    /// When <see langword="true"/> (the default), every packet carries a 15-bit picture ID (M=1) that
    /// increments once per frame and wraps modulo <see cref="PictureIdModulus"/>. When
    /// <see langword="false"/>, only the mandatory one-byte descriptor is emitted.
    /// </param>
    public Vp9Packetizer(bool includePictureId = true)
    {
        _includePictureId = includePictureId;
    }

    /// <inheritdoc />
    public uint ClockRate => Vp9ClockRate;

    /// <summary>
    /// Always zero: like VP8 and H.264, VP9's RTP payload format does not encode frame duration, so the
    /// caller must supply capture timestamps.
    /// </summary>
    /// <param name="frame">The encoded VP9 frame; ignored.</param>
    /// <returns>Zero.</returns>
    public uint GetTimestampIncrement(ReadOnlySpan<byte> frame) => 0;

    private int DescriptorLength => _includePictureId
        ? MandatoryDescriptorLength + ExtendedPictureIdLength
        : MandatoryDescriptorLength;

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="writer"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="maxPayloadSize"/> leaves no room for the descriptor plus at least one payload byte.
    /// </exception>
    public int Packetize(ReadOnlySpan<byte> frame, uint rtpTimestamp, int maxPayloadSize, IRtpPayloadWriter writer)
    {
        // VP9's marker bit means end-of-frame, not talkspurt start, so the RTP timestamp plays no part
        // in it, exactly as for VP8 and H.264.
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
        var isKeyFrame = Vp9FrameHeader.IsKeyFrame(frame);

        var maxFragment = maxPayloadSize - descriptorLength;
        var position = 0;
        var packets = 0;

        while (position < frame.Length)
        {
            var length = Math.Min(maxFragment, frame.Length - position);
            var isFirst = position == 0;
            var isLast = position + length == frame.Length;

            var buffer = writer.GetPayloadBuffer(length + descriptorLength);
            WriteDescriptor(buffer, isFirst, isLast, isKeyFrame, pictureId);
            frame.Slice(position, length).CopyTo(buffer[descriptorLength..]);

            position += length;
            writer.Commit(length + descriptorLength, isLast);
            packets++;
        }

        return packets;
    }

    private void WriteDescriptor(Span<byte> buffer, bool startOfFrame, bool endOfFrame, bool keyFrame, ushort pictureId)
    {
        // Byte 0 (draft-ietf-payload-vp9 §4.2): I|P|L|F|B|E|V|Z. L (layer indices), F (flexible mode),
        // V (scalability structure) and Z (non-reference) stay clear: this is a single-layer,
        // non-flexible packetization. P=0 marks a key frame, so a receiver detects it from the
        // descriptor without parsing the bitstream.
        byte descriptor = 0;
        if (!keyFrame)
        {
            descriptor |= InterPicturePredicted;
        }

        if (startOfFrame)
        {
            descriptor |= StartOfFrame;
        }

        if (endOfFrame)
        {
            descriptor |= EndOfFrame;
        }

        if (!_includePictureId)
        {
            buffer[0] = descriptor;
            return;
        }

        buffer[0] = (byte)(descriptor | PictureIdPresent); // I=1
        buffer[1] = (byte)(0x80 | (pictureId >> 8)); // M=1, high 7 bits of the 15-bit picture ID
        buffer[2] = (byte)pictureId; // low 8 bits
    }
}
