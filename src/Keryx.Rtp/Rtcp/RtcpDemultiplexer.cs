namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Distinguishes RTP from RTCP on a single rtcp-mux'ed port (RFC 5761 §4).
/// </summary>
/// <remarks>
/// RFC 5761 reserves RTP payload types 64–95 so that, once the marker bit is folded in, the second
/// byte of an RTCP packet always falls in the range 192–223 while the second byte of an RTP packet
/// never does. The check is therefore a single byte-range test on the second octet.
/// </remarks>
public static class RtcpDemultiplexer
{
    /// <summary>Lowest second-octet value that identifies an RTCP packet (RTCP packet type 192).</summary>
    public const byte MinRtcpPacketType = 192;

    /// <summary>Highest second-octet value that identifies an RTCP packet (RTCP packet type 223).</summary>
    public const byte MaxRtcpPacketType = 223;

    /// <summary>Returns whether a demultiplexed datagram should be handled as RTCP.</summary>
    /// <param name="packet">The datagram, after SRTP/SRTCP demultiplexing decisions but before decryption.</param>
    /// <returns><see langword="true"/> when the second octet lies in the RTCP range 192–223.</returns>
    public static bool IsRtcp(ReadOnlySpan<byte> packet) =>
        packet.Length >= 2 && packet[1] >= MinRtcpPacketType && packet[1] <= MaxRtcpPacketType;

    /// <summary>Returns whether a demultiplexed datagram should be handled as RTP.</summary>
    /// <param name="packet">The datagram.</param>
    /// <returns><see langword="true"/> when the datagram is long enough to be RTP and is not RTCP.</returns>
    public static bool IsRtp(ReadOnlySpan<byte> packet) =>
        packet.Length >= RtpHeader.FixedLength && !IsRtcp(packet);
}
