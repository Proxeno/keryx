using FluentAssertions;
using Keryx.Rtp;
using Xunit;

namespace Keryx.Rtp.Tests;

/// <summary>Coverage for RFC 8285 §4.2 one-byte-header extension elements.</summary>
public class RtpHeaderExtensionTests
{
    [Fact]
    public void Enumerates_one_byte_header_elements()
    {
        // RFC 8285 §4.2: each element is ID (4 bits) | len-1 (4 bits), then len octets of data.
        // Element 3 carries the transport-wide sequence number, element 1 a two-octet value.
        byte[] extension = [0x10, 0xAA, 0x31, 0x01, 0x02, 0x00, 0x00, 0x00];

        var enumerator = new RtpOneByteExtensionEnumerator(extension);

        enumerator.MoveNext().Should().BeTrue();
        enumerator.Current.Id.Should().Be(1);
        enumerator.Current.Data.ToArray().Should().Equal(0xAA);

        enumerator.MoveNext().Should().BeTrue();
        enumerator.Current.Id.Should().Be(3);
        enumerator.Current.Data.ToArray().Should().Equal(0x01, 0x02);

        enumerator.MoveNext().Should().BeFalse();
    }

    [Fact]
    public void Stops_at_the_reserved_identifier_fifteen()
    {
        // RFC 8285 §4.2: "the ID value 15 ... the rest of the extension is to be ignored."
        byte[] extension = [0x10, 0xAA, 0xF0, 0x20, 0xBB, 0xCC];
        var enumerator = new RtpOneByteExtensionEnumerator(extension);

        enumerator.MoveNext().Should().BeTrue();
        enumerator.Current.Id.Should().Be(1);
        enumerator.MoveNext().Should().BeFalse();
    }

    [Fact]
    public void Ignores_an_element_whose_length_runs_past_the_extension()
    {
        byte[] extension = [0x1F, 0xAA, 0xBB];
        var enumerator = new RtpOneByteExtensionEnumerator(extension);
        enumerator.MoveNext().Should().BeFalse();
    }

    [Fact]
    public void Writes_and_reads_back_extension_elements_through_the_header()
    {
        Span<byte> scratch = stackalloc byte[32];
        var writer = new RtpOneByteExtensionWriter(scratch);
        writer.TryAppend(3, [0x00, 0x2A]).Should().BeTrue();   // transport-wide sequence number 42
        writer.TryAppend(4, "mid"u8).Should().BeTrue();        // a=mid
        var length = writer.Finish();
        // (1 + 2) + (1 + 3) = 7 octets, padded to the next 32-bit boundary per RFC 3550 §5.3.1.
        length.Should().Be(8);

        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = 96,
            HasExtension = true,
            ExtensionProfile = RtpHeaderExtension.OneByteProfile,
            ExtensionData = scratch[..length],
        };

        Span<byte> packet = stackalloc byte[64];
        var written = header.WriteTo(packet);

        RtpHeader.TryParse(packet[..written], out var parsed).Should().BeTrue();
        parsed.TryGetExtension(3, out var seq).Should().BeTrue();
        seq.ToArray().Should().Equal(0x00, 0x2A);
        parsed.TryGetExtension(4, out var mid).Should().BeTrue();
        mid.ToArray().Should().Equal("mid"u8.ToArray());
        parsed.TryGetExtension(7, out _).Should().BeFalse();
    }

    [Fact]
    public void Extension_elements_are_not_enumerated_for_other_profiles()
    {
        var header = new RtpHeader
        {
            Version = 2,
            HasExtension = true,
            ExtensionProfile = 0x1234,
            ExtensionData = new byte[] { 0x10, 0xAA, 0x00, 0x00 },
        };

        var count = 0;
        foreach (var _ in header.GetExtensionElements())
        {
            count++;
        }

        count.Should().Be(0);
    }
}
