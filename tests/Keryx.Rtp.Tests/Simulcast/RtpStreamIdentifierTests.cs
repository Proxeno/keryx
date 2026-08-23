using FluentAssertions;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Xunit;

namespace Keryx.Rtp.Tests.Simulcast;

public class RtpStreamIdentifierTests
{
    [Fact]
    public void TryGetRid_ReadsTheRidElement()
    {
        var packet = SimulcastTestPackets.WithRid("hi", ssrc: 0x1111, seq: 10, ts: 1000);
        RtpHeader.TryParse(packet, out var header).Should().BeTrue();

        RtpStreamIdentifier.TryGetRid(header, SimulcastTestPackets.RidId, out var layer).Should().BeTrue();
        layer.ToString().Should().Be("hi");
    }

    [Fact]
    public void TryGetRepairedRid_ReadsTheRepairedRidElement()
    {
        var packet = SimulcastTestPackets.WithRepairedRid("lo", ssrc: 0x2222, seq: 5, ts: 500);
        RtpHeader.TryParse(packet, out var header).Should().BeTrue();

        RtpStreamIdentifier.TryGetRepairedRid(header, SimulcastTestPackets.RepairedRidId, out var layer).Should().BeTrue();
        layer.ToString().Should().Be("lo");
    }

    [Fact]
    public void TryGetRid_ReturnsFalseWhenExtensionAbsent()
    {
        var packet = SimulcastTestPackets.Plain(ssrc: 0x3333, seq: 1, ts: 90);
        RtpHeader.TryParse(packet, out var header).Should().BeTrue();

        RtpStreamIdentifier.TryGetRid(header, SimulcastTestPackets.RidId, out _).Should().BeFalse();
    }

    [Fact]
    public void TryGetRid_ReturnsFalseWhenExtensionNotNegotiated()
    {
        var packet = SimulcastTestPackets.WithRid("hi", ssrc: 0x4444, seq: 1, ts: 90);
        RtpHeader.TryParse(packet, out var header).Should().BeTrue();

        // Element id 0 means the RID extension was not negotiated.
        RtpStreamIdentifier.TryGetRid(header, 0, out _).Should().BeFalse();
    }

    [Fact]
    public void TryGetMid_and_TryGetRid_read_correctly_under_two_byte_encoding()
    {
        // A browser emits the two-byte (0x1000) profile for the whole extension block when any single
        // element in it needs one — here an unrelated, densely negotiated extension (id 20, standing in
        // for something like abs-capture-time) forces it even though MID and RID are both short.
        const byte midId = SimulcastTestPackets.MidId;
        const byte ridId = SimulcastTestPackets.RidId;
        const byte otherId = 20;

        Span<byte> scratch = stackalloc byte[64];
        var writer = new RtpTwoByteExtensionWriter(scratch);
        writer.TryAppend(midId, "0"u8).Should().BeTrue();
        writer.TryAppend(ridId, "high"u8).Should().BeTrue();
        writer.TryAppend(otherId, [0xDE, 0xAD, 0xBE, 0xEF]).Should().BeTrue();
        var length = writer.Finish();

        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = 96,
            SequenceNumber = 1,
            Timestamp = 1000,
            Ssrc = 0x5555,
            HasExtension = true,
            ExtensionProfile = RtpHeaderExtension.TwoByteProfile,
            ExtensionData = scratch[..length],
        };

        Span<byte> packet = stackalloc byte[96];
        var written = header.WriteTo(packet);
        RtpHeader.TryParse(packet[..written], out var parsed).Should().BeTrue();

        RtpStreamIdentifier.TryGetMid(parsed, midId, out var mid).Should().BeTrue();
        mid.ToArray().Should().Equal("0"u8.ToArray());

        RtpStreamIdentifier.TryGetRid(parsed, ridId, out var rid).Should().BeTrue();
        rid.ToString().Should().Be("high");

        parsed.TryGetExtension(otherId, out var other).Should().BeTrue();
        other.ToArray().Should().Equal(0xDE, 0xAD, 0xBE, 0xEF);
    }
}
