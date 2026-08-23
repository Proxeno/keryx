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

    [Fact]
    public void Enumerates_two_byte_header_elements()
    {
        // RFC 8285 §4.3: each element is a one-byte id, a one-byte length, then that many octets.
        byte[] extension = [1, 1, 0xAA, 3, 2, 0x01, 0x02];
        var enumerator = new RtpTwoByteExtensionEnumerator(extension);

        enumerator.MoveNext().Should().BeTrue();
        enumerator.Current.Id.Should().Be(1);
        enumerator.Current.Data.ToArray().Should().Equal(0xAA);

        enumerator.MoveNext().Should().BeTrue();
        enumerator.Current.Id.Should().Be(3);
        enumerator.Current.Data.ToArray().Should().Equal(0x01, 0x02);

        enumerator.MoveNext().Should().BeFalse();
    }

    [Fact]
    public void Two_byte_form_skips_padding_and_allows_a_zero_length_element()
    {
        // id 0 is padding (RFC 8285 §4.3); a declared length of 0 is valid and distinct from padding.
        byte[] extension = [0, 0, 5, 0, 2, 2, 0xBB, 0xCC];
        var enumerator = new RtpTwoByteExtensionEnumerator(extension);

        enumerator.MoveNext().Should().BeTrue();
        enumerator.Current.Id.Should().Be(5);
        enumerator.Current.Data.ToArray().Should().BeEmpty();

        enumerator.MoveNext().Should().BeTrue();
        enumerator.Current.Id.Should().Be(2);
        enumerator.Current.Data.ToArray().Should().Equal(0xBB, 0xCC);

        enumerator.MoveNext().Should().BeFalse();
    }

    [Fact]
    public void Two_byte_form_has_no_reserved_stop_identifier()
    {
        // Unlike the one-byte form, id 15 is an ordinary identifier in the two-byte form.
        byte[] extension = [15, 1, 0xAA];
        var enumerator = new RtpTwoByteExtensionEnumerator(extension);

        enumerator.MoveNext().Should().BeTrue();
        enumerator.Current.Id.Should().Be(15);
        enumerator.Current.Data.ToArray().Should().Equal(0xAA);
    }

    [Fact]
    public void Two_byte_form_ignores_an_element_whose_length_runs_past_the_extension()
    {
        byte[] extension = [1, 5, 0xAA, 0xBB];
        var enumerator = new RtpTwoByteExtensionEnumerator(extension);
        enumerator.MoveNext().Should().BeFalse();
    }

    [Fact]
    public void Writes_and_reads_back_two_byte_extension_elements_through_the_header()
    {
        Span<byte> scratch = stackalloc byte[64];
        var writer = new RtpTwoByteExtensionWriter(scratch);
        writer.TryAppend(20, [0x00, 0x2A]).Should().BeTrue();   // an id beyond the one-byte range (1-14)
        writer.TryAppend(4, "mid"u8).Should().BeTrue();         // a=mid
        var length = writer.Finish();
        // (2 + 2) + (2 + 3) = 9 octets, padded to the next 32-bit boundary per RFC 3550 §5.3.1.
        length.Should().Be(12);

        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = 96,
            HasExtension = true,
            ExtensionProfile = RtpHeaderExtension.TwoByteProfile,
            ExtensionData = scratch[..length],
        };

        Span<byte> packet = stackalloc byte[64];
        var written = header.WriteTo(packet);

        RtpHeader.TryParse(packet[..written], out var parsed).Should().BeTrue();
        parsed.TryGetExtension(20, out var seq).Should().BeTrue();
        seq.ToArray().Should().Equal(0x00, 0x2A);
        parsed.TryGetExtension(4, out var mid).Should().BeTrue();
        mid.ToArray().Should().Equal("mid"u8.ToArray());
        parsed.TryGetExtension(7, out _).Should().BeFalse();
    }

    [Theory]
    [InlineData(0x1000)] // appbits nibble 0x0
    [InlineData(0x1005)] // a negotiated appbits nibble
    [InlineData(0x100F)] // appbits nibble 0xF
    public void Two_byte_profile_is_matched_with_the_appbits_nibble_masked_off(ushort profile)
    {
        var header = new RtpHeader
        {
            Version = 2,
            HasExtension = true,
            ExtensionProfile = profile,
            ExtensionData = [4, 3, (byte)'m', (byte)'i', (byte)'d', 0],
        };

        header.TryGetExtension(4, out var mid).Should().BeTrue();
        mid.ToArray().Should().Equal((byte)'m', (byte)'i', (byte)'d');
    }

    [Fact]
    public void An_id_that_is_not_masked_to_the_two_byte_profile_is_not_enumerated()
    {
        // 0x2000 shares no bits with the masked two-byte profile 0x1000 and is not 0xBEDE either.
        var header = new RtpHeader
        {
            Version = 2,
            HasExtension = true,
            ExtensionProfile = 0x2000,
            ExtensionData = [4, 3, (byte)'m', (byte)'i', (byte)'d', 0],
        };

        header.TryGetExtension(4, out _).Should().BeFalse();
    }

    [Theory]
    [InlineData(1, 1, false)]
    [InlineData(14, 16, false)]
    [InlineData(15, 1, true)]     // id beyond the one-byte range (1-14)
    [InlineData(1, 17, true)]     // body beyond the one-byte range (1-16 bytes)
    [InlineData(1, 0, true)]      // zero-length body: one-byte's length nibble cannot express it
    public void RequiresTwoByteProfile_reflects_the_one_byte_forms_limits(byte id, int dataLength, bool expected) =>
        RtpHeaderExtension.RequiresTwoByteProfile(id, dataLength).Should().Be(expected);

    [Fact]
    public void Chooses_two_byte_encoding_when_an_id_exceeds_the_one_byte_range()
    {
        const byte ridElementId = 15; // browsers may negotiate ids beyond 14 (RFC 8285 §4.2 reserves 15)
        byte[] rid = "hi"u8.ToArray();

        var useTwoByte = RtpHeaderExtension.RequiresTwoByteProfile(ridElementId, rid.Length);
        useTwoByte.Should().BeTrue();

        Span<byte> scratch = stackalloc byte[16];
        var written = WriteExtensionBody(useTwoByte, scratch, ridElementId, rid);

        var header = new RtpHeader
        {
            Version = 2,
            HasExtension = true,
            ExtensionProfile = useTwoByte ? RtpHeaderExtension.TwoByteProfile : RtpHeaderExtension.OneByteProfile,
            ExtensionData = written,
        };

        Span<byte> packet = stackalloc byte[64];
        var length = header.WriteTo(packet);
        RtpHeader.TryParse(packet[..length], out var parsed).Should().BeTrue();
        parsed.TryGetExtension(ridElementId, out var data).Should().BeTrue();
        data.ToArray().Should().Equal(rid);
    }

    [Fact]
    public void Chooses_two_byte_encoding_when_a_body_exceeds_sixteen_bytes()
    {
        const byte elementId = 7;
        var body = "this-value-is-longer-than-sixteen-bytes"u8.ToArray();

        var useTwoByte = RtpHeaderExtension.RequiresTwoByteProfile(elementId, body.Length);
        useTwoByte.Should().BeTrue();

        Span<byte> scratch = stackalloc byte[64];
        var written = WriteExtensionBody(useTwoByte, scratch, elementId, body);

        var header = new RtpHeader
        {
            Version = 2,
            HasExtension = true,
            ExtensionProfile = useTwoByte ? RtpHeaderExtension.TwoByteProfile : RtpHeaderExtension.OneByteProfile,
            ExtensionData = written,
        };

        Span<byte> packet = stackalloc byte[128];
        var length = header.WriteTo(packet);
        RtpHeader.TryParse(packet[..length], out var parsed).Should().BeTrue();
        parsed.TryGetExtension(elementId, out var data).Should().BeTrue();
        data.ToArray().Should().Equal(body);
    }

    [Fact]
    public void Stays_with_one_byte_encoding_when_every_element_fits_it()
    {
        const byte elementId = 3;
        byte[] body = [0x01, 0x02];

        RtpHeaderExtension.RequiresTwoByteProfile(elementId, body.Length).Should().BeFalse();
    }

    private static ReadOnlySpan<byte> WriteExtensionBody(bool twoByte, Span<byte> scratch, byte id, ReadOnlySpan<byte> data)
    {
        if (twoByte)
        {
            var writer = new RtpTwoByteExtensionWriter(scratch);
            writer.TryAppend(id, data).Should().BeTrue();
            return scratch[..writer.Finish()];
        }
        else
        {
            var writer = new RtpOneByteExtensionWriter(scratch);
            writer.TryAppend(id, data).Should().BeTrue();
            return scratch[..writer.Finish()];
        }
    }
}
