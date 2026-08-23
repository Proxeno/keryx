using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// <see cref="PeerConnection.CreateAnswerAsync"/> must negotiate the answered <c>a=</c> direction
/// attribute from the offered direction rather than hardcoding <c>recvonly</c>. Keryx answers as a
/// sender only when the offer is <c>recvonly</c> — the SFU subscriber shape, where a viewer offers
/// recvonly and Keryx answers sendonly and forwards media on its own SSRC; for every other offered
/// direction its local capability stays receive-only. These tests pin down what
/// <see cref="SdpDirection.Negotiate"/> returns against each of the four offered directions, matching
/// RFC 3264 §6.1's answer rules.
/// </summary>
public sealed class AnswererDirectionNegotiationTests
{
    [Theory]
    [InlineData("sendrecv", "recvonly")] // offerer will send and receive; Keryx only receives.
    [InlineData("sendonly", "recvonly")] // offerer only sends; Keryx receives it.
    [InlineData("recvonly", "sendonly")] // offerer only receives; Keryx answers as the sender.
    [InlineData("inactive", "inactive")] // neither side transmits.
    public async Task AnswersTheDirectionRfc3264Demands(
        string offeredDirection,
        string expectedAnsweredDirection)
    {
        var cancellationToken = TestTimeout();

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        var retargeted = WithDirection(offer, "audio", offeredDirection);

        await answerer.SetRemoteDescriptionAsync(retargeted, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);

        var parsed = SessionDescription.Parse(answer);
        var audio = parsed.MediaDescriptions.Single(m => m.Media == "audio");
        audio.DirectionOrDefault.ToAttributeName().Should().Be(expectedAnsweredDirection);

        answer.Should().Contain($"a={expectedAnsweredDirection}");
    }

    /// <summary>
    /// Replaces the offerer's explicit direction attribute (<see cref="SdpMediaOffer"/> always writes
    /// one for RTP sections) on the named m-section with <paramref name="direction"/>, leaving the
    /// rest of the offer untouched.
    /// </summary>
    private static string WithDirection(string sdp, string mediaType, string direction)
    {
        var lines = sdp.ReplaceLineEndings("\n").Split('\n').ToList();

        var start = lines.FindIndex(l => l.StartsWith($"m={mediaType} ", StringComparison.Ordinal));
        start.Should().BeGreaterThanOrEqualTo(0, $"the offer must contain an m={mediaType} section");

        var next = lines.FindIndex(start + 1, l => l.StartsWith("m=", StringComparison.Ordinal));
        var end = next < 0 ? lines.Count : next;

        var directionIndex = lines.FindIndex(
            start,
            end - start,
            l => l is "a=sendrecv" or "a=sendonly" or "a=recvonly" or "a=inactive");
        directionIndex.Should().BeGreaterThanOrEqualTo(0, "the offerer always writes an explicit direction");

        lines[directionIndex] = $"a={direction}";
        return string.Join("\r\n", lines);
    }

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(20)).Token;
}
