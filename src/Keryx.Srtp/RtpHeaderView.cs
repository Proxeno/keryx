using Keryx.Core;

namespace Keryx.Srtp;

/// <summary>
/// The minimal RTP fixed-header parse SRTP needs: where the payload starts, which SSRC the packet
/// belongs to and its sequence number. Keryx.Srtp deliberately does not depend on Keryx.Rtp.
/// </summary>
internal static class RtpHeaderView
{
    /// <summary>Length of the RTP fixed header (RFC 3550 Section 5.1).</summary>
    public const int FixedHeaderLength = 12;

    /// <summary>Minimum length of an RTCP packet header plus the SSRC of the sender.</summary>
    public const int RtcpHeaderLength = 8;

    /// <summary>
    /// Parses the RTP header. Returns false for anything that is not a well-formed RTP packet
    /// rather than throwing, because this runs on wire data.
    /// </summary>
    /// <param name="packet">The RTP (or SRTP) packet.</param>
    /// <param name="headerLength">
    /// On success, the number of leading octets that form the RTP header, including the CSRC list
    /// and any header extension. RFC 3711 Section 3.1 places the header extension inside the
    /// authenticated portion but outside the encrypted portion, so this is where encryption starts.
    /// </param>
    /// <param name="ssrc">On success, the synchronisation source.</param>
    /// <param name="sequenceNumber">On success, the RTP sequence number.</param>
    public static bool TryParse(
        ReadOnlySpan<byte> packet,
        out int headerLength,
        out uint ssrc,
        out ushort sequenceNumber)
    {
        headerLength = 0;
        ssrc = 0;
        sequenceNumber = 0;

        if (packet.Length < FixedHeaderLength)
        {
            return false;
        }

        var first = packet[0];
        if ((first >> 6) != 2)
        {
            return false;
        }

        var csrcCount = first & 0x0F;
        var hasExtension = (first & 0x10) != 0;

        var length = FixedHeaderLength + (csrcCount * 4);
        if (packet.Length < length)
        {
            return false;
        }

        if (hasExtension)
        {
            if (packet.Length < length + 4)
            {
                return false;
            }

            var extension = new ByteReader(packet.Slice(length, 4));
            _ = extension.ReadU16();
            var words = extension.ReadU16();
            length += 4 + (words * 4);
            if (packet.Length < length)
            {
                return false;
            }
        }

        var reader = new ByteReader(packet[..FixedHeaderLength]);
        reader.Skip(2);
        sequenceNumber = reader.ReadU16();
        reader.Skip(4);
        ssrc = reader.ReadU32();

        headerLength = length;
        return true;
    }

    /// <summary>
    /// Reads the SSRC of the first packet in an RTCP compound packet, which RFC 3711 Section 4.1.1
    /// designates as the SSRC used to build the SRTCP IV.
    /// </summary>
    /// <param name="packet">The RTCP (or SRTCP) packet.</param>
    /// <param name="ssrc">On success, the SSRC of the sender.</param>
    public static bool TryParseRtcp(ReadOnlySpan<byte> packet, out uint ssrc)
    {
        ssrc = 0;
        if (packet.Length < RtcpHeaderLength)
        {
            return false;
        }

        if ((packet[0] >> 6) != 2)
        {
            return false;
        }

        var reader = new ByteReader(packet[..RtcpHeaderLength]);
        reader.Skip(4);
        ssrc = reader.ReadU32();
        return true;
    }
}
