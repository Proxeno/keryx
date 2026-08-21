using FluentAssertions;
using Keryx.Rtp.Packetization;
using Xunit;

namespace Keryx.Rtp.Tests.Packetization;

/// <summary>Coverage for the Annex B NAL unit scanner (ITU-T H.264 Annex B).</summary>
public class AnnexBTests
{
    [Fact]
    public void Finds_nal_units_delimited_by_four_byte_start_codes()
    {
        byte[] stream =
        [
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42,
            0x00, 0x00, 0x00, 0x01, 0x68, 0xCE,
            0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84,
        ];

        var nals = Collect(stream);
        nals.Should().HaveCount(3);
        nals[0].Should().Equal(0x67, 0x42);
        nals[1].Should().Equal(0x68, 0xCE);
        nals[2].Should().Equal(0x65, 0x88, 0x84);
    }

    [Fact]
    public void Finds_nal_units_delimited_by_three_byte_start_codes()
    {
        byte[] stream = [0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x00, 0x01, 0x65, 0x88];

        var nals = Collect(stream);
        nals.Should().HaveCount(2);
        nals[0].Should().Equal(0x67, 0x42);
        nals[1].Should().Equal(0x65, 0x88);
    }

    [Fact]
    public void Handles_a_mixture_of_three_and_four_byte_start_codes()
    {
        byte[] stream =
        [
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42,
            0x00, 0x00, 0x01, 0x68, 0xCE,
            0x00, 0x00, 0x00, 0x01, 0x65, 0x88,
        ];

        var nals = Collect(stream);
        nals.Should().HaveCount(3);
        nals[1].Should().Equal(0x68, 0xCE);
        nals[2].Should().Equal(0x65, 0x88);
    }

    [Fact]
    public void Leading_bytes_before_the_first_start_code_are_skipped()
    {
        byte[] stream = [0xFF, 0xEE, 0x00, 0x00, 0x01, 0x65, 0x01];
        Collect(stream).Should().ContainSingle().Which.Should().Equal(0x65, 0x01);
    }

    [Fact]
    public void An_empty_nal_between_two_start_codes_is_skipped()
    {
        byte[] stream = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x65, 0x01];
        Collect(stream).Should().ContainSingle().Which.Should().Equal(0x65, 0x01);
    }

    [Fact]
    public void A_stream_with_no_start_code_yields_nothing()
    {
        Collect([0x65, 0x01, 0x02]).Should().BeEmpty();
        AnnexB.CountNalUnits([0x65, 0x01, 0x02]).Should().Be(0);
    }

    [Fact]
    public void Counts_nal_units()
    {
        byte[] stream =
        [
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42,
            0x00, 0x00, 0x00, 0x01, 0x68, 0xCE,
            0x00, 0x00, 0x00, 0x01, 0x65, 0x88,
        ];

        AnnexB.CountNalUnits(stream).Should().Be(3);
    }

    [Theory]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x01 }, 4)]
    [InlineData(new byte[] { 0x00, 0x00, 0x01 }, 3)]
    [InlineData(new byte[] { 0x00, 0x00, 0x02 }, 0)]
    [InlineData(new byte[] { 0x00, 0x01 }, 0)]
    public void Recognises_start_code_lengths(byte[] data, int expected)
    {
        AnnexB.StartCodeLengthAt(data, 0).Should().Be(expected);
    }

    private static List<byte[]> Collect(byte[] stream)
    {
        var result = new List<byte[]>();
        var enumerator = AnnexB.EnumerateNalUnits(stream);
        while (enumerator.MoveNext())
        {
            result.Add(enumerator.Current.ToArray());
        }

        return result;
    }
}
