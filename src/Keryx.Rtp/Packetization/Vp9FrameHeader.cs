namespace Keryx.Rtp.Packetization;

/// <summary>
/// Parses just enough of a VP9 uncompressed frame header to tell a key frame from an inter frame
/// (VP9 bitstream specification §6.2 "uncompressed_header").
/// </summary>
/// <remarks>
/// The full uncompressed header is large, but the frame type sits within the first handful of bits, so
/// this reads only the leading bits: the two-bit frame marker, the profile bits, the
/// <c>show_existing_frame</c> flag and the <c>frame_type</c> flag. Anything malformed is treated as
/// "not a key frame" rather than throwing — the packetizer's descriptor is a hint, and a wrong guess
/// degrades gracefully to an inter-frame marking.
/// </remarks>
internal static class Vp9FrameHeader
{
    private const int FrameMarker = 2; // uncompressed_header: frame_marker f(2) == 0b10

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="frame"/> begins with a VP9 key frame
    /// (<c>frame_type == 0</c>), <see langword="false"/> for an inter frame, a shown existing frame, or
    /// any header too short or malformed to classify.
    /// </summary>
    /// <param name="frame">The encoded VP9 frame.</param>
    /// <returns>Whether the frame is a key frame.</returns>
    public static bool IsKeyFrame(ReadOnlySpan<byte> frame)
    {
        if (frame.IsEmpty)
        {
            return false;
        }

        var reader = new BitReader(frame);

        if (!reader.TryRead(2, out var marker) || marker != FrameMarker)
        {
            return false;
        }

        if (!reader.TryRead(1, out var profileLow) || !reader.TryRead(1, out var profileHigh))
        {
            return false;
        }

        var profile = (profileHigh << 1) | profileLow;
        if (profile == 3)
        {
            // profile 3 carries a reserved_zero bit before show_existing_frame.
            if (!reader.TryRead(1, out _))
            {
                return false;
            }
        }

        if (!reader.TryRead(1, out var showExistingFrame))
        {
            return false;
        }

        if (showExistingFrame == 1)
        {
            // A repeat of an already-decoded frame: never a key frame.
            return false;
        }

        // frame_type: 0 = KEY_FRAME, 1 = NON_KEY_FRAME.
        return reader.TryRead(1, out var frameType) && frameType == 0;
    }

    /// <summary>A big-endian bit reader over a byte span, bounded so it never reads past the end.</summary>
    private ref struct BitReader(ReadOnlySpan<byte> data)
    {
        private readonly ReadOnlySpan<byte> _data = data;
        private int _bitPosition;

        public bool TryRead(int bitCount, out int value)
        {
            value = 0;
            if (bitCount <= 0 || bitCount > 24)
            {
                return false;
            }

            for (var i = 0; i < bitCount; i++)
            {
                var byteIndex = _bitPosition >> 3;
                if (byteIndex >= _data.Length)
                {
                    return false;
                }

                var bit = (_data[byteIndex] >> (7 - (_bitPosition & 7))) & 1;
                value = (value << 1) | bit;
                _bitPosition++;
            }

            return true;
        }
    }
}
