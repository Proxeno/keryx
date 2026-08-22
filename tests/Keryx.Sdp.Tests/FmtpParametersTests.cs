using FluentAssertions;
using Xunit;

namespace Keryx.Sdp.Tests;

public class FmtpParametersTests
{
    [Fact]
    public void Parse_SplitsKeyValuePairs()
    {
        var parameters = FmtpParameters.Parse("level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f");

        parameters.Should().HaveCount(3);
        parameters["level-asymmetry-allowed"].Should().Be("1");
        parameters["packetization-mode"].Should().Be("1");
        parameters["profile-level-id"].Should().Be("42e01f");
    }

    [Fact]
    public void Parse_TrimsWhitespaceAroundTokens()
    {
        var parameters = FmtpParameters.Parse("minptime=10; useinbandfec=1 ");

        parameters["minptime"].Should().Be("10");
        parameters["useinbandfec"].Should().Be("1");
    }

    [Fact]
    public void Parse_TreatsValuelessTokensAsEmptyValues()
    {
        var parameters = FmtpParameters.Parse("0-16");

        parameters.Should().ContainKey("0-16").WhoseValue.Should().BeEmpty();
    }

    [Fact]
    public void Parse_KeepsValuesContainingEqualsSigns()
    {
        FmtpParameters.Parse("x=a=b")["x"].Should().Be("a=b");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Parse_BlankInputYieldsAnEmptyLookup(string? value)
    {
        FmtpParameters.Parse(value).Should().BeEmpty();
    }

    [Fact]
    public void Parse_IsCaseSensitive()
    {
        var parameters = FmtpParameters.Parse("apt=96");

        parameters.Should().ContainKey("apt");
        parameters.Should().NotContainKey("APT");
    }

    [Fact]
    public void GetValue_ReturnsNullForMissingKeys()
    {
        FmtpParameters.GetValue("apt=96", "apt").Should().Be("96");
        FmtpParameters.GetValue("apt=96", "profile-level-id").Should().BeNull();
    }

    [Fact]
    public void Matches_ComparesValuesCaseInsensitively()
    {
        const string fmtp = "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f";

        FmtpParameters.Matches(fmtp, "profile-level-id", "42E01F").Should().BeTrue();
        FmtpParameters.Matches(fmtp, "packetization-mode", "1").Should().BeTrue();
        FmtpParameters.Matches(fmtp, "packetization-mode", "0").Should().BeFalse();
        FmtpParameters.Matches(fmtp, "absent", "1").Should().BeFalse();
    }

    [Fact]
    public void Format_JoinsWithSemicolonsAndNoSpaces()
    {
        var text = FmtpParameters.Format(
        [
            new KeyValuePair<string, string>("minptime", "10"),
            new KeyValuePair<string, string>("useinbandfec", "1"),
        ]);

        text.Should().Be("minptime=10;useinbandfec=1");
    }

    [Fact]
    public void Format_EmitsBareKeysForEmptyValues()
    {
        FmtpParameters.Format([new KeyValuePair<string, string>("0-16", string.Empty)]).Should().Be("0-16");
    }

    [Fact]
    public void GetFmtpParameters_ReadsFromTheMediaSection()
    {
        var video = SessionDescription.Parse(SdpTestData.ChromeOffer).MediaDescriptions[1];

        video.GetFmtpParameters(102)["profile-level-id"].Should().Be("42e01f");
        video.GetFmtpParameters(96)["profile-level-id"].Should().Be("42001f");
        video.GetFmtpParameters(404).Should().BeEmpty();
    }
}
