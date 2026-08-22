using FluentAssertions;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.Rtcp;

/// <summary>Coverage for traversing compound RTCP packets (RFC 3550 §6.1).</summary>
public class RtcpCompoundReaderTests
{
    private static byte[] BuildCompound()
    {
        var report = new RtcpReceiverReport { SenderSsrc = 0x1111_1111 };
        var sdes = RtcpSourceDescription.CreateCname(0x1111_1111, "keryx");
        var pli = new RtcpPictureLossIndication(0x1111_1111, 0x2222_2222);

        // An APP packet (PT=204) stands in for a type Keryx does not model.
        byte[] app = [0x80, 204, 0x00, 0x02, 0x11, 0x11, 0x11, 0x11, (byte)'T', (byte)'E', (byte)'S', (byte)'T'];

        var buffer = new byte[report.Length + sdes.Length + app.Length + pli.Length];
        var offset = report.WriteTo(buffer);
        offset += sdes.WriteTo(buffer.AsSpan(offset));
        app.CopyTo(buffer.AsSpan(offset));
        offset += app.Length;
        pli.WriteTo(buffer.AsSpan(offset));
        return buffer;
    }

    [Fact]
    public void Walks_every_sub_packet_including_unknown_types()
    {
        var compound = BuildCompound();
        var types = new List<RtcpPacketType>();

        var reader = new RtcpCompoundReader(compound);
        while (reader.MoveNext())
        {
            types.Add(reader.Current.Header.PacketType);
            reader.Current.Packet.Length.Should().Be(reader.Current.Header.PacketLength);
        }

        reader.IsMalformed.Should().BeFalse();
        types.Should().Equal(
            RtcpPacketType.ReceiverReport,
            RtcpPacketType.SourceDescription,
            RtcpPacketType.ApplicationDefined,
            RtcpPacketType.PayloadSpecificFeedback);
    }

    [Fact]
    public void ParseCompound_returns_typed_packets_and_preserves_unknown_ones()
    {
        var packets = RtcpPacket.ParseCompound(BuildCompound());

        packets.Should().HaveCount(4);
        packets[0].Should().BeOfType<RtcpReceiverReport>();
        packets[1].Should().BeOfType<RtcpSourceDescription>();
        packets[2].Should().BeOfType<RtcpUnknownPacket>();
        packets[3].Should().BeOfType<RtcpPictureLossIndication>();

        var unknown = (RtcpUnknownPacket)packets[2];
        unknown.PacketType.Should().Be(RtcpPacketType.ApplicationDefined);
        unknown.Length.Should().Be(12);
    }

    [Fact]
    public void Compound_round_trips_through_WriteCompound()
    {
        var original = BuildCompound();
        var packets = RtcpPacket.ParseCompound(original);

        var rebuilt = new byte[original.Length];
        var written = RtcpPacket.WriteCompound(packets, rebuilt);

        written.Should().Be(original.Length);
        rebuilt.Should().Equal(original);
    }

    [Fact]
    public void Stops_and_reports_a_sub_packet_whose_length_runs_past_the_buffer()
    {
        var compound = BuildCompound();
        var truncated = compound.AsSpan(0, compound.Length - 4).ToArray();

        var reader = new RtcpCompoundReader(truncated);
        var count = 0;
        while (reader.MoveNext())
        {
            count++;
        }

        count.Should().Be(3);
        reader.IsMalformed.Should().BeTrue();
    }

    [Fact]
    public void Stops_at_a_sub_packet_with_the_wrong_version()
    {
        var compound = BuildCompound();
        var firstLength = (((compound[2] << 8) | compound[3]) + 1) * 4;
        compound[firstLength] = 0x00; // version 0 on the second sub-packet

        var reader = new RtcpCompoundReader(compound);
        reader.MoveNext().Should().BeTrue();
        reader.MoveNext().Should().BeFalse();
        reader.IsMalformed.Should().BeTrue();
    }

    [Fact]
    public void An_empty_buffer_yields_nothing()
    {
        var reader = new RtcpCompoundReader([]);
        reader.MoveNext().Should().BeFalse();
        reader.IsMalformed.Should().BeFalse();
    }
}
