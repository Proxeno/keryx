namespace Keryx.Rtp;

/// <summary>
/// A parsed view over one RTP packet (RFC 3550 §5.1): its header plus the payload, with any
/// RFC 3550 padding removed.
/// </summary>
/// <remarks>
/// Both the header spans and <see cref="Payload"/> alias the buffer the packet was parsed from; the
/// view is valid only while that buffer is.
/// </remarks>
public readonly ref struct RtpPacket
{
    /// <summary>Creates a packet view from an already parsed header and payload.</summary>
    /// <param name="header">The RTP header.</param>
    /// <param name="payload">The payload, excluding padding.</param>
    /// <param name="paddingLength">Number of padding octets that followed the payload.</param>
    public RtpPacket(RtpHeader header, ReadOnlySpan<byte> payload, int paddingLength = 0)
    {
        Header = header;
        Payload = payload;
        PaddingLength = paddingLength;
    }

    /// <summary>The packet's header.</summary>
    public RtpHeader Header { get; }

    /// <summary>The payload, with RFC 3550 §5.1 padding octets already stripped.</summary>
    public ReadOnlySpan<byte> Payload { get; }

    /// <summary>Number of padding octets that followed the payload; zero when the P bit is clear.</summary>
    public int PaddingLength { get; }

    /// <summary>
    /// Parses a complete RTP packet, validating the header and the padding count.
    /// </summary>
    /// <param name="buffer">The whole RTP packet as received.</param>
    /// <param name="packet">On success, a view over <paramref name="buffer"/>.</param>
    /// <returns>
    /// <see langword="false"/> when the header is malformed (see <see cref="RtpHeader.TryParse"/>) or
    /// when the P bit is set but the trailing padding count is zero or larger than the remaining bytes.
    /// </returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtpPacket packet)
    {
        packet = default;

        if (!RtpHeader.TryParse(buffer, out var header))
        {
            return false;
        }

        var payload = buffer[header.HeaderLength..];
        var padding = 0;

        if (header.HasPadding)
        {
            if (payload.Length == 0)
            {
                return false;
            }

            padding = payload[^1];
            if (padding == 0 || padding > payload.Length)
            {
                return false;
            }

            payload = payload[..^padding];
        }

        packet = new RtpPacket(header, payload, padding);
        return true;
    }
}
