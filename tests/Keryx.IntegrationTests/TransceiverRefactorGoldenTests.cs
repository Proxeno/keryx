using System.Text;
using System.Text.RegularExpressions;
using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// The §5.4 correctness anchors for the internal transceiver refactor (PR 2): the offer Keryx builds
/// from the default config, and the answers it produces to a browser <c>sendrecv</c> offer, a
/// <c>recvonly</c> offer and a simulcast offer, must be byte-identical before and after the refactor.
/// The SDP is normalized only for the values that are random by construction — the <c>o=</c> session
/// id, ICE credentials, the DTLS fingerprint, gathered candidates, and the synchronisation sources
/// (mapped to stable role tokens by first appearance) — everything the refactor could actually move
/// (mids, m-line order, directions, codecs, fmtp, rtcp-fb, extmaps, ssrc-group structure, msid) is
/// asserted verbatim against a golden captured from <c>main</c>.
/// </summary>
public sealed partial class TransceiverRefactorGoldenTests
{
    private const string GoldenDirectory = "assets/golden";

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(20)).Token;

    /// <summary>A config with the random identifiers pinned so only the truly random SDP fields vary.</summary>
    private static PeerConnectionConfig GoldenConfig()
    {
        var config = TestSupport.NewConfig();
        config.Cname = "keryx-test-cname";
        config.StreamId = "stream-test";
        config.VideoTrackId = "video-test";
        config.AudioTrackId = "audio-test";
        return config;
    }

    [Fact]
    public async Task GoldenOffer_DefaultConfig_IsByteIdentical()
    {
        await using var peer = new PeerConnection(GoldenConfig());
        var offer = await peer.CreateOfferAsync(TestTimeout());
        AssertGolden("offer-default", offer);
    }

    [Fact]
    public async Task GoldenAnswer_ToSendrecvOffer_IsByteIdentical()
    {
        var offer = await CapturedOfferAsync(retargetBothTo: "sendrecv");
        var answer = await AnswerToAsync(offer);
        AssertGolden("answer-sendrecv", answer);
    }

    [Fact]
    public async Task GoldenAnswer_ToRecvonlyOffer_IsByteIdentical()
    {
        var offer = await CapturedOfferAsync(retargetBothTo: "recvonly");
        var answer = await AnswerToAsync(offer);
        AssertGolden("answer-recvonly", answer);
    }

    [Fact]
    public async Task GoldenAnswer_ToSimulcastOffer_IsByteIdentical()
    {
        var offer = await SimulcastOfferAsync();
        var answer = await AnswerToAsync(offer);
        AssertGolden("answer-simulcast", answer);
    }

    /// <summary>
    /// A genuine-shape Chrome offer (audio-first, <c>sendrecv</c>, carrying the RFC 8843 §9.2 MID header
    /// extension at element id 9) — the case the synthetic Keryx-offer fixtures cannot represent, because
    /// a Keryx offer carries no MID extmap. It pins the one deliberate legacy-answerer SDP change 0.3.0
    /// makes over 0.2.x: the answer now echoes the MID extmap the browser offered, on every RTP m-line,
    /// at the offered id — the shipped vuefix broadcaster/ingest PCs answer real Chrome offers, so this
    /// change is on their path and must be locked.
    /// </summary>
    [Fact]
    public async Task GoldenAnswer_ToRealChromeOffer_EchoesMidExtmap()
    {
        var offer = await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "assets", "chrome-offer.sdp"));
        var answer = await AnswerToAsync(offer);

        var parsed = SessionDescription.Parse(answer);
        foreach (var media in parsed.MediaDescriptions.Where(m => m.Media is "audio" or "video"))
        {
            media.GetExtMaps().Should().Contain(
                e => e.Id == 9 && string.Equals(e.Uri, RtpHeaderExtensionUri.Mid, StringComparison.Ordinal),
                "the 0.3.0 answer echoes the browser's MID extmap on every RTP m-line, at the offered id");
        }

        AssertGolden("answer-chrome", answer);
    }

    /// <summary>
    /// Builds a Keryx offer, then rewrites every RTP m-line's direction to <paramref name="retargetBothTo"/>,
    /// standing in for a browser offer of that shape.
    /// </summary>
    private static async Task<string> CapturedOfferAsync(string retargetBothTo)
    {
        await using var offerer = new PeerConnection(GoldenConfig());
        var baseOffer = await offerer.CreateOfferAsync(TestTimeout());

        var parsed = SessionDescription.Parse(baseOffer);
        foreach (var media in parsed.MediaDescriptions)
        {
            if (media.Media is "video" or "audio")
            {
                media.Direction = DirectionFromName(retargetBothTo);
            }
        }

        return parsed.ToSdpString();
    }

    /// <summary>Builds a Keryx offer and turns its video section into an RFC 8852 simulcast section.</summary>
    private static async Task<string> SimulcastOfferAsync()
    {
        await using var offerer = new PeerConnection(GoldenConfig());
        var baseOffer = await offerer.CreateOfferAsync(TestTimeout());

        var parsed = SessionDescription.Parse(baseOffer);
        var video = parsed.MediaDescriptions.First(m => string.Equals(m.Media, "video", StringComparison.Ordinal));
        video.AddExtMap(new SdpExtMap(4, RtpHeaderExtensionUri.Mid));
        video.AddExtMap(new SdpExtMap(5, RtpHeaderExtensionUri.Rid));
        video.AddExtMap(new SdpExtMap(6, RtpHeaderExtensionUri.RepairedRid));
        video.AddRid(new SdpRid("hi", RidDirection.Send, new[] { new SdpRidRestriction("max-width", "1280") }));
        video.AddRid(new SdpRid("mid", RidDirection.Send));
        video.AddRid(new SdpRid("lo", RidDirection.Send));
        video.Simulcast = SdpSimulcast.SendOnly(
            new SdpSimulcastStream("hi"),
            new SdpSimulcastStream("mid"),
            new SdpSimulcastStream("lo"));

        return parsed.ToSdpString();
    }

    private static async Task<string> AnswerToAsync(string offer)
    {
        await using var answerer = new PeerConnection(GoldenConfig());
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, TestTimeout());
        return await answerer.CreateAnswerAsync(TestTimeout());
    }

    private static MediaDirection DirectionFromName(string name) => name switch
    {
        "sendrecv" => MediaDirection.SendRecv,
        "sendonly" => MediaDirection.SendOnly,
        "recvonly" => MediaDirection.RecvOnly,
        "inactive" => MediaDirection.Inactive,
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, "Unknown direction."),
    };

    private static void AssertGolden(string name, string sdp)
    {
        var normalized = Normalize(sdp);
        var path = Path.Combine(AppContext.BaseDirectory, GoldenDirectory, name + ".sdp");

        if (!File.Exists(path))
        {
            // Capture mode: record the golden from the current (pre-refactor) code, then fail loudly so
            // the capture is never silently mistaken for a passing assertion.
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, normalized);
            Assert.Fail($"Captured golden '{name}' to {path}; re-run to assert against it.");
        }

        var expected = File.ReadAllText(path).ReplaceLineEndings("\n");
        normalized.ReplaceLineEndings("\n").Should().Be(
            expected,
            $"the refactor must not change the '{name}' SDP");
    }

    /// <summary>
    /// Replaces the by-construction-random SDP fields with stable placeholders so two runs of the same
    /// logical description compare equal, while leaving every structural field intact.
    /// </summary>
    private static string Normalize(string sdp)
    {
        var lines = sdp.ReplaceLineEndings("\n").Split('\n');
        var ssrcTokens = new Dictionary<string, string>(StringComparer.Ordinal);
        var builder = new StringBuilder();

        foreach (var raw in lines)
        {
            var line = raw;
            if (line.StartsWith("a=candidate:", StringComparison.Ordinal))
            {
                continue;
            }

            if (line.StartsWith("o=", StringComparison.Ordinal))
            {
                line = "o=- SESSIONID 2 IN IP4 127.0.0.1";
            }
            else if (line.StartsWith("a=ice-ufrag:", StringComparison.Ordinal))
            {
                line = "a=ice-ufrag:NORM";
            }
            else if (line.StartsWith("a=ice-pwd:", StringComparison.Ordinal))
            {
                line = "a=ice-pwd:NORM";
            }
            else if (line.StartsWith("a=fingerprint:", StringComparison.Ordinal))
            {
                line = "a=fingerprint:sha-256 NORM";
            }
            else if (line.StartsWith("a=ssrc-group:", StringComparison.Ordinal)
                     || line.StartsWith("a=ssrc:", StringComparison.Ordinal))
            {
                line = SsrcPattern().Replace(line, match =>
                {
                    var value = match.Value;
                    if (!ssrcTokens.TryGetValue(value, out var token))
                    {
                        token = "SSRC" + ssrcTokens.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
                        ssrcTokens[value] = token;
                    }

                    return token;
                });
            }

            builder.Append(line).Append('\n');
        }

        return builder.ToString();
    }

    // Matches an SSRC integer that stands alone (whole token), so cname/msid text on the same line is
    // left untouched.
    [GeneratedRegex(@"(?<![\w.-])\d{4,}(?![\w.-])")]
    private static partial Regex SsrcPattern();
}
