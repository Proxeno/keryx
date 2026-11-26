using FluentAssertions;
using Keryx.Rtp.Packetization;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Checks the barge-in tone fixtures parse as 20 ms Opus packets, so the Chrome pump can stamp one
/// RTP packet per media frame.
/// </summary>
public sealed class OggOpusReaderTests
{
    [Theory]
    [InlineData("tone-440.ogg")]
    [InlineData("tone-880.ogg")]
    public void ToneAssetYieldsTwentyMillisecondOpusPackets(string fileName)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "assets", fileName);
        var packets = OggOpusReader.ReadPackets(path);

        // 1.5 s at 20 ms per packet is 75 packets.
        packets.Should().HaveCountGreaterThanOrEqualTo(70);
        packets.Should().HaveCountLessThanOrEqualTo(80);
        packets.Should().OnlyContain(packet => OpusPacketizer.GetDurationMicroseconds(packet) == 20_000);
    }
}
