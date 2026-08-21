using FluentAssertions;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.Rtcp;

/// <summary>Round-trip coverage for SDES (RFC 3550 §6.5) and BYE (RFC 3550 §6.6).</summary>
public class RtcpSdesAndByeTests
{
    [Fact]
    public void Cname_chunk_round_trips_and_is_word_aligned()
    {
        // RFC 3550 §6.5: "the list of items in each chunk MUST be terminated by one or more null
        // octets ... padded out to the next 32-bit boundary."
        var sdes = RtcpSourceDescription.CreateCname(0x1234_5678, "keryx@example");

        var bytes = sdes.ToByteArray();
        (bytes.Length % 4).Should().Be(0);
        bytes[0].Should().Be(0x81); // V=2, SC=1
        bytes[1].Should().Be(202);
        bytes[8].Should().Be((byte)RtcpSdesItemType.Cname);
        bytes[9].Should().Be(13);

        RtcpSourceDescription.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.Chunks.Should().ContainSingle();
        parsed.Chunks[0].Ssrc.Should().Be(0x1234_5678);
        parsed.Chunks[0].Cname.Should().Be("keryx@example");
    }

    [Theory]
    [InlineData("a")]
    [InlineData("ab")]
    [InlineData("abc")]
    [InlineData("abcd")]
    [InlineData("abcde")]
    public void Cname_of_every_length_modulo_four_stays_word_aligned(string cname)
    {
        var bytes = RtcpSourceDescription.CreateCname(1, cname).ToByteArray();
        (bytes.Length % 4).Should().Be(0);
        RtcpSourceDescription.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.Chunks[0].Cname.Should().Be(cname);
    }

    [Fact]
    public void Multiple_items_and_chunks_round_trip()
    {
        var sdes = new RtcpSourceDescription();
        var first = new RtcpSdesChunk(1);
        first.Items.Add(new RtcpSdesItem(RtcpSdesItemType.Cname, "one"));
        first.Items.Add(new RtcpSdesItem(RtcpSdesItemType.Tool, "keryx"));
        var second = new RtcpSdesChunk(2);
        second.Items.Add(new RtcpSdesItem(RtcpSdesItemType.Cname, "two"));
        sdes.Chunks.Add(first);
        sdes.Chunks.Add(second);

        var bytes = sdes.ToByteArray();
        bytes[0].Should().Be(0x82);

        RtcpSourceDescription.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.Chunks.Should().HaveCount(2);
        parsed.Chunks[0].Items.Should().HaveCount(2);
        parsed.Chunks[0].Items[1].Type.Should().Be(RtcpSdesItemType.Tool);
        parsed.Chunks[0].Items[1].Value.Should().Be("keryx");
        parsed.Chunks[1].Cname.Should().Be("two");
    }

    [Fact]
    public void Bye_with_a_reason_round_trips()
    {
        // RFC 3550 §6.6: the optional reason is a length-prefixed string padded to a 32-bit boundary.
        var bye = new RtcpGoodbye(0xDEAD_BEEF, "teardown");

        var bytes = bye.ToByteArray();
        (bytes.Length % 4).Should().Be(0);
        bytes[0].Should().Be(0x81);
        bytes[1].Should().Be(203);

        RtcpGoodbye.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.Sources.Should().Equal(0xDEAD_BEEFu);
        parsed.Reason.Should().Be("teardown");
    }

    [Fact]
    public void Bye_without_a_reason_round_trips()
    {
        var bye = new RtcpGoodbye();
        bye.Sources.Add(1);
        bye.Sources.Add(2);

        var bytes = bye.ToByteArray();
        bytes.Length.Should().Be(12);

        RtcpGoodbye.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.Sources.Should().Equal(1u, 2u);
        parsed.Reason.Should().BeNull();
    }

    [Fact]
    public void Bye_rejects_a_reason_longer_than_the_length_field()
    {
        var bye = new RtcpGoodbye();
        var act = () => bye.Reason = new string('x', 256);
        act.Should().Throw<ArgumentException>();
    }
}
