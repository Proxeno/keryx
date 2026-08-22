using FluentAssertions;
using Keryx.Core;
using Keryx.Rtp;
using Xunit;

namespace Keryx.Rtp.Tests;

/// <summary>
/// Edge-case coverage for the fixed RTP header of RFC 3550 §5.1 and the header extension of §5.3.1.
/// </summary>
public class RtpHeaderTests
{
    // V=2, P=0, X=0, CC=0 | M=1, PT=96 | seq=0x1234 | ts=0xDEADBEEF | ssrc=0xCAFEBABE
    private static readonly byte[] Minimal =
    [
        0x80, 0xE0, 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    ];

    [Fact]
    public void Parses_minimal_twelve_byte_header()
    {
        // RFC 3550 §5.1: the fixed header is 12 octets and is present in every RTP packet.
        RtpHeader.TryParse(Minimal, out var header).Should().BeTrue();

        header.Version.Should().Be(2);
        header.HasPadding.Should().BeFalse();
        header.HasExtension.Should().BeFalse();
        header.CsrcCount.Should().Be(0);
        header.Marker.Should().BeTrue();
        header.PayloadType.Should().Be(96);
        header.SequenceNumber.Should().Be(0x1234);
        header.Timestamp.Should().Be(0xDEADBEEF);
        header.Ssrc.Should().Be(0xCAFEBABE);
        header.HeaderLength.Should().Be(12);
    }

    [Fact]
    public void Marker_and_payload_type_share_the_second_octet()
    {
        // RFC 3550 §5.1: M is the top bit of the second octet, PT the low seven bits.
        var bytes = (byte[])Minimal.Clone();
        bytes[1] = 0x60; // M=0, PT=96
        RtpHeader.TryParse(bytes, out var header).Should().BeTrue();
        header.Marker.Should().BeFalse();
        header.PayloadType.Should().Be(96);

        bytes[1] = 0xFF; // M=1, PT=127
        RtpHeader.TryParse(bytes, out header).Should().BeTrue();
        header.Marker.Should().BeTrue();
        header.PayloadType.Should().Be(127);
    }

    [Theory]
    [InlineData(0x00)] // version 0
    [InlineData(0x40)] // version 1
    [InlineData(0xC0)] // version 3
    public void Rejects_versions_other_than_two(byte firstOctet)
    {
        // RFC 3550 §5.1: "The version defined by this specification is two (2)."
        var bytes = (byte[])Minimal.Clone();
        bytes[0] = (byte)(firstOctet | (Minimal[0] & 0x3F));
        RtpHeader.TryParse(bytes, out _).Should().BeFalse();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(8)]
    [InlineData(11)]
    public void Rejects_a_header_truncated_before_the_fixed_twelve_octets(int length)
    {
        RtpHeader.TryParse(Minimal.AsSpan(0, length), out _).Should().BeFalse();
    }

    [Fact]
    public void Parses_a_header_with_csrcs()
    {
        // RFC 3550 §5.1: CC counts the CSRC identifiers that follow the fixed header, 4 octets each.
        var bytes = new byte[12 + 8];
        Minimal.CopyTo(bytes, 0);
        bytes[0] = 0x82; // V=2, CC=2
        bytes[12] = 0x00; bytes[13] = 0x00; bytes[14] = 0x00; bytes[15] = 0x11;
        bytes[16] = 0xAA; bytes[17] = 0xBB; bytes[18] = 0xCC; bytes[19] = 0xDD;

        RtpHeader.TryParse(bytes, out var header).Should().BeTrue();
        header.CsrcCount.Should().Be(2);
        header.HeaderLength.Should().Be(20);
        header.GetCsrc(0).Should().Be(0x00000011);
        header.GetCsrc(1).Should().Be(0xAABBCCDD);
    }

    [Theory]
    [InlineData(12)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(19)]
    public void Rejects_a_csrc_list_truncated_at_every_boundary(int length)
    {
        var bytes = new byte[12 + 8];
        Minimal.CopyTo(bytes, 0);
        bytes[0] = 0x82;
        RtpHeader.TryParse(bytes.AsSpan(0, length), out _).Should().BeFalse();
    }

    [Fact]
    public void Parses_a_header_extension()
    {
        // RFC 3550 §5.3.1: X=1 adds a 16-bit profile identifier, a 16-bit length in 32-bit words,
        // and that many words of extension data.
        var bytes = new byte[12 + 4 + 8];
        Minimal.CopyTo(bytes, 0);
        bytes[0] = 0x90; // V=2, X=1
        bytes[12] = 0xBE; bytes[13] = 0xDE; // profile
        bytes[14] = 0x00; bytes[15] = 0x02; // two 32-bit words
        for (var i = 0; i < 8; i++)
        {
            bytes[16 + i] = (byte)(0xA0 + i);
        }

        RtpHeader.TryParse(bytes, out var header).Should().BeTrue();
        header.HasExtension.Should().BeTrue();
        header.ExtensionProfile.Should().Be(0xBEDE);
        header.ExtensionData.Length.Should().Be(8);
        header.ExtensionData.ToArray().Should().Equal(0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7);
        header.HeaderLength.Should().Be(24);
    }

    [Theory]
    [InlineData(12)] // no room for the profile/length word at all
    [InlineData(13)]
    [InlineData(15)] // profile/length word itself truncated
    [InlineData(16)] // length word claims 2 words, none present
    [InlineData(20)] // only one of the two words present
    [InlineData(23)] // one octet short of the declared extension
    public void Rejects_an_extension_truncated_at_every_boundary(int length)
    {
        var bytes = new byte[12 + 4 + 8];
        Minimal.CopyTo(bytes, 0);
        bytes[0] = 0x90;
        bytes[12] = 0xBE; bytes[13] = 0xDE;
        bytes[14] = 0x00; bytes[15] = 0x02;
        RtpHeader.TryParse(bytes.AsSpan(0, length), out _).Should().BeFalse();
    }

    [Fact]
    public void Parses_csrcs_and_an_extension_together()
    {
        var bytes = new byte[12 + 4 + 4 + 4];
        Minimal.CopyTo(bytes, 0);
        bytes[0] = 0x91; // V=2, X=1, CC=1
        bytes[12] = 0x01; bytes[13] = 0x02; bytes[14] = 0x03; bytes[15] = 0x04; // CSRC
        bytes[16] = 0xBE; bytes[17] = 0xDE;
        bytes[18] = 0x00; bytes[19] = 0x01;
        bytes[20] = 0x11; bytes[21] = 0x22; bytes[22] = 0x33; bytes[23] = 0x44;

        RtpHeader.TryParse(bytes, out var header).Should().BeTrue();
        header.CsrcCount.Should().Be(1);
        header.GetCsrc(0).Should().Be(0x01020304);
        header.ExtensionData.ToArray().Should().Equal(0x11, 0x22, 0x33, 0x44);
        header.HeaderLength.Should().Be(24);
    }

    [Fact]
    public void Padding_bit_is_reported_but_does_not_affect_the_header_length()
    {
        // RFC 3550 §5.1: padding octets sit at the end of the payload, not inside the header.
        var bytes = (byte[])Minimal.Clone();
        bytes[0] = 0xA0; // V=2, P=1
        RtpHeader.TryParse(bytes, out var header).Should().BeTrue();
        header.HasPadding.Should().BeTrue();
        header.HeaderLength.Should().Be(12);
    }

    [Fact]
    public void Round_trips_a_header_with_csrcs_and_an_extension()
    {
        Span<byte> csrcs = stackalloc byte[8];
        csrcs[3] = 0x11;
        csrcs[4] = 0xAA; csrcs[5] = 0xBB; csrcs[6] = 0xCC; csrcs[7] = 0xDD;
        Span<byte> extension = [0xDE, 0xAD, 0xBE, 0xEF];

        var header = new RtpHeader
        {
            Version = 2,
            HasPadding = true,
            Marker = true,
            PayloadType = 111,
            SequenceNumber = 0xFFFE,
            Timestamp = 0x01020304,
            Ssrc = 0x0A0B0C0D,
            CsrcData = csrcs,
            HasExtension = true,
            ExtensionProfile = RtpHeaderExtension.OneByteProfile,
            ExtensionData = extension,
        };

        Span<byte> buffer = stackalloc byte[64];
        var written = header.WriteTo(buffer);
        written.Should().Be(header.HeaderLength).And.Be(28);

        RtpHeader.TryParse(buffer[..written], out var parsed).Should().BeTrue();
        parsed.HasPadding.Should().BeTrue();
        parsed.Marker.Should().BeTrue();
        parsed.PayloadType.Should().Be(111);
        parsed.SequenceNumber.Should().Be(0xFFFE);
        parsed.Timestamp.Should().Be(0x01020304u);
        parsed.Ssrc.Should().Be(0x0A0B0C0Du);
        parsed.GetCsrc(1).Should().Be(0xAABBCCDD);
        parsed.ExtensionProfile.Should().Be(0xBEDE);
        parsed.ExtensionData.ToArray().Should().Equal(0xDE, 0xAD, 0xBE, 0xEF);
    }

    [Fact]
    public void TryWriteTo_reports_a_destination_that_is_too_small()
    {
        var header = new RtpHeader { Version = 2, PayloadType = 96 };
        Span<byte> small = stackalloc byte[11];
        header.TryWriteTo(small, out var written).Should().BeFalse();
        written.Should().Be(0);
    }

    [Fact]
    public void WriteTo_throws_a_ByteBufferException_when_the_destination_is_too_small()
    {
        var thrown = Record.Exception(() =>
        {
            var header = new RtpHeader { Version = 2, PayloadType = 96 };
            Span<byte> small = stackalloc byte[8];
            header.WriteTo(small);
        });

        thrown.Should().BeOfType<ByteBufferException>();
    }

    [Fact]
    public void WriteTo_rejects_more_than_fifteen_csrcs()
    {
        var thrown = Record.Exception(() =>
        {
            var header = new RtpHeader { Version = 2, CsrcData = new byte[16 * 4] };
            header.WriteTo(new byte[256]);
        });

        thrown.Should().BeOfType<InvalidOperationException>();
    }

    [Fact]
    public void WriteTo_rejects_an_extension_body_that_is_not_word_aligned()
    {
        var thrown = Record.Exception(() =>
        {
            var header = new RtpHeader
            {
                Version = 2,
                HasExtension = true,
                ExtensionProfile = RtpHeaderExtension.OneByteProfile,
                ExtensionData = new byte[3],
            };
            header.WriteTo(new byte[64]);
        });

        thrown.Should().BeOfType<InvalidOperationException>();
    }
}
