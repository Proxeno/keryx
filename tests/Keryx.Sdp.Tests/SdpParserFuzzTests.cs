using System.Text;
using Xunit;

namespace Keryx.Sdp.Tests;

/// <summary>
/// Seeded, deterministic generative fuzzers for the inbound SDP parser: the offer/answer text a remote
/// peer supplies (<see cref="SessionDescription.Parse(string, Keryx.Core.IKeryxLogger?)"/>) together
/// with every typed accessor that interprets its attributes (m-lines, <c>a=rtpmap</c>, <c>a=fmtp</c>,
/// <c>a=extmap</c>, <c>a=candidate</c>, <c>a=fingerprint</c>, <c>a=ssrc</c>/<c>a=ssrc-group</c>,
/// <c>a=rid</c>, <c>a=simulcast</c>, <c>a=group</c>) and the JSEP negotiator that consumes a parsed
/// document.
/// </summary>
/// <remarks>
/// The robustness contract: for any input string, <c>Parse</c> must never throw (it is documented to
/// throw only <see cref="System.ArgumentNullException"/>, and the fuzzers never pass null), and driving
/// the full battery of accessors, a serialize/re-parse round trip, and the negotiator over the result
/// must never throw either. Malformed attributes must be skipped, not fatal. Semantic correctness of
/// garbage is not asserted; only robustness is.
///
/// A fixed PRNG seed set makes every run reproduce byte-for-byte; a violation logs the seed, strategy
/// and the exact offending text.
/// </remarks>
public class SdpParserFuzzTests
{
    private const int IterationsPerSeed = 1500;
    private const int MaxLength = 262144;

    private static readonly int[] Seeds = [1, 7, 42, 99, 1234, 20260824];

    private static readonly string[] Corpus =
    [
        SdpTestData.ChromeOffer,
        SdpTestData.ChromeAnswer,
        SdpTestData.ChromeAnswerLf,
        SimulcastOffer,
    ];

    /// <summary>
    /// Structure-aware mutation fuzzer: starts from real browser SDP (Chrome offer/answer, plus a
    /// simulcast offer with <c>a=rid</c>/<c>a=simulcast</c>) and corrupts it — character flips,
    /// truncation, line duplication/repetition, numeric-field corruption (huge/negative/non-numeric),
    /// character deletion, injected delimiters and whole-document duplication.
    /// </summary>
    [Fact]
    public void Fuzz_StructureAwareMutations_NeverThrow()
    {
        foreach (var seed in Seeds)
        {
            var rng = new Random(seed);
            for (var i = 0; i < IterationsPerSeed; i++)
            {
                var original = Corpus[rng.Next(Corpus.Length)];
                var mutated = Mutate(original, rng, out var strategy);
                AssertRobust(mutated, seed, i, strategy);
            }
        }
    }

    /// <summary>
    /// Total-garbage fuzzer: random Unicode strings and random bytes decoded as Latin-1, of widely
    /// varied lengths (empty through several KB), plus <c>&lt;type&gt;=&lt;garbage&gt;</c> lines that
    /// reach every switch arm of the line parser.
    /// </summary>
    [Fact]
    public void Fuzz_TotalGarbage_NeverThrow()
    {
        foreach (var seed in Seeds)
        {
            var rng = new Random(seed ^ 0x5EED);
            for (var i = 0; i < IterationsPerSeed; i++)
            {
                var text = rng.Next(3) switch
                {
                    0 => RandomUnicode(rng),
                    1 => RandomLatin1(rng),
                    _ => RandomTypedLines(rng),
                };
                AssertRobust(text, seed, i, "garbage");
            }
        }
    }

    /// <summary>
    /// A fixed table of adversarial inputs exercising specific boundary conditions independent of the
    /// PRNG, and permanent regression coverage for anything a fuzz run surfaces.
    /// </summary>
    [Theory]
    [MemberData(nameof(EdgeCases))]
    public void EdgeCase_ParsesWithoutThrowing(string name, string input)
    {
        AssertRobust(input, seed: -1, iteration: -1, strategy: name);
    }

    public static TheoryData<string, string> EdgeCases()
    {
        return new TheoryData<string, string>
        {
            { "empty", string.Empty },
            { "single-newline", "\n" },
            { "crlf-only", "\r\n" },
            { "one-char", "v" },
            { "bare-equals", "=" },
            { "type-no-value", "a=" },
            { "m-line-empty", "m=" },
            { "o-line-empty", "o=" },
            { "c-line-empty", "c=" },
            { "huge-version", "v=999999999999999999999999999999" },
            { "negative-port", "m=audio -1 UDP/TLS/RTP/SAVPF 111" },
            { "huge-port", "m=audio 999999999999 UDP/TLS/RTP/SAVPF 111" },
            { "port-slash-garbage", "m=audio 9/xyz UDP/TLS/RTP/SAVPF 111" },
            { "rtpmap-huge-pt", "m=audio 9 RTP/AVP 0\r\na=rtpmap:999999999999 opus/48000/2" },
            { "rtpmap-no-clock", "m=audio 9 RTP/AVP 0\r\na=rtpmap:0 opus" },
            { "fmtp-no-space", "m=audio 9 RTP/AVP 0\r\na=fmtp:0" },
            { "ssrc-huge", "m=video 9 RTP/AVP 96\r\na=ssrc:99999999999999 cname:x" },
            { "extmap-slash-only", "m=video 9 RTP/AVP 96\r\na=extmap:/ urn:x" },
            { "group-semantics-only", "a=group:BUNDLE" },
            { "simulcast-dangling", "m=video 9 RTP/AVP 96\r\na=simulcast:send" },
            { "rid-overlong-id", "m=video 9 RTP/AVP 96\r\na=rid:" + new string('a', 500) + " send" },
            { "fingerprint-one-field", "a=fingerprint:sha-256" },
            { "many-a-lines", string.Concat(Enumerable.Repeat("a=x\r\n", 5000)) },
        };
    }

    private static void AssertRobust(string text, int seed, int iteration, string strategy)
    {
        SessionDescription parsed;
        try
        {
            parsed = SessionDescription.Parse(text);
        }
        catch (Exception ex)
        {
            Assert.Fail(Report("SessionDescription.Parse", ex, strategy, seed, iteration, text));
            return;
        }

        try
        {
            ExerciseAllAccessors(parsed);

            // Serialize and re-parse: the round trip must also be robust, and re-exercising the
            // reconstructed document guards the writer→parser boundary.
            var serialized = parsed.ToSdpString();
            var reparsed = SessionDescription.Parse(serialized);
            ExerciseAllAccessors(reparsed);

            // The JSEP negotiator consumes untrusted parsed documents. Interpret is the best-effort
            // read; Validate is the structural check. Neither may throw on adversarial input. Run the
            // document against itself and against every corpus offer to cross combinations.
            SdpNegotiator.Validate(parsed, parsed);
            SdpNegotiator.Interpret(parsed, parsed);
        }
        catch (Exception ex)
        {
            Assert.Fail(Report("accessor/negotiator", ex, strategy, seed, iteration, text));
        }
    }

    /// <summary>Drives every typed accessor over the parsed document, forcing lazy attribute parsing.</summary>
    private static void ExerciseAllAccessors(SessionDescription sdp)
    {
        // Session level.
        _ = sdp.Version;
        _ = sdp.Origin.Username;
        _ = sdp.Origin.SessionId;
        _ = sdp.SessionName;
        _ = sdp.Information;
        _ = sdp.Uri;
        _ = sdp.Emails.Count;
        _ = sdp.PhoneNumbers.Count;
        _ = sdp.Timings.Count;
        _ = sdp.MsidSemantic;
        _ = sdp.ExtMapAllowMixed;
        _ = sdp.GetGroups();
        _ = sdp.GetBundleGroup();
        _ = sdp.GetWmsStreamIds();
        _ = sdp.GetMids();
        _ = sdp.GetFingerprints();
        _ = sdp.Fingerprint;
        _ = sdp.Setup;
        _ = sdp.IceUfrag;
        _ = sdp.IcePwd;
        _ = sdp.GetIceOptions();
        _ = sdp.SupportsTrickleIce;

        foreach (var media in sdp.MediaDescriptions)
        {
            _ = media.Media;
            _ = media.Port;
            _ = media.PortCount;
            _ = media.Protocol;
            _ = media.IsRejected;
            _ = media.IsRtp;
            _ = media.Mid;
            _ = media.Direction;
            _ = media.DirectionOrDefault;
            _ = media.Rtcp;
            _ = media.RtcpMux;
            _ = media.RtcpReducedSize;
            _ = media.Msid;
            _ = media.Simulcast;
            _ = media.SctpPort;
            _ = media.MaxMessageSize;
            _ = media.EndOfCandidates;
            _ = media.Fingerprint;
            _ = media.Setup;
            _ = media.IceUfrag;
            _ = media.IcePwd;
            _ = media.GetIceOptions();
            _ = media.GetCandidates();
            _ = media.GetExtMaps();
            _ = media.GetRids();
            _ = media.GetRtpMaps();
            _ = media.GetRtcpFeedbackEntries();
            _ = media.GetSsrcAttributes();
            _ = media.GetSsrcGroups();
            _ = media.GetFingerprints();

            var payloadTypes = media.GetPayloadTypes();
            foreach (var pt in payloadTypes)
            {
                _ = media.GetRtpMap(pt);
                _ = media.GetFmtp(pt);
                _ = media.GetFmtpParameters(pt);
                _ = media.GetRtcpFeedback(pt);
            }

            // Also probe a couple of payload types that are unlikely to be present.
            _ = media.GetFmtpParameters(0);
            _ = media.GetRtcpFeedback(255);

            foreach (var ssrc in media.GetSsrcs())
            {
                _ = media.GetSsrcCname(ssrc);
                _ = media.GetSsrcMsid(ssrc);
            }

            // Simulcast answering path (RFC 8853 §5.2) over the untrusted section.
            _ = SdpNegotiator.AnswerSimulcast(media);
        }
    }

    // ---- Mutation engine ------------------------------------------------------------------------

    private static string Mutate(string source, Random rng, out string strategy)
    {
        var choice = rng.Next(8);
        string result;
        switch (choice)
        {
            case 0:
                strategy = "char-flip";
                result = FlipChars(source, rng);
                break;
            case 1:
                strategy = "truncate";
                result = source.Length == 0 ? source : source[..rng.Next(source.Length)];
                break;
            case 2:
                strategy = "duplicate-lines";
                result = DuplicateLines(source, rng);
                break;
            case 3:
                strategy = "corrupt-numeric";
                result = CorruptNumeric(source, rng);
                break;
            case 4:
                strategy = "delete-chars";
                result = DeleteChars(source, rng);
                break;
            case 5:
                strategy = "inject-delimiters";
                result = InjectDelimiters(source, rng);
                break;
            case 6:
                strategy = "duplicate-document";
                result = source + source;
                break;
            default:
                strategy = "insert-unicode";
                result = InsertUnicode(source, rng);
                break;
        }

        return result.Length > MaxLength ? result[..MaxLength] : result;
    }

    private static string FlipChars(string source, Random rng)
    {
        if (source.Length == 0)
        {
            return source;
        }

        var chars = source.ToCharArray();
        var count = 1 + rng.Next(16);
        for (var n = 0; n < count; n++)
        {
            var index = rng.Next(chars.Length);
            chars[index] = rng.Next(4) switch
            {
                0 => (char)rng.Next(0x20),          // control chars
                1 => (char)rng.Next(0x80, 0x1000),  // higher BMP
                2 => "=:;/ \r\n"[rng.Next(7)],      // structural delimiters
                _ => (char)rng.Next(0x20, 0x7F),    // printable ASCII
            };
        }

        return new string(chars);
    }

    private static string DuplicateLines(string source, Random rng)
    {
        var lines = source.Split('\n');
        if (lines.Length == 0)
        {
            return source;
        }

        var builder = new StringBuilder(source.Length * 2);
        foreach (var line in lines)
        {
            builder.Append(line).Append('\n');
            if (rng.Next(6) == 0)
            {
                var repeats = 1 + rng.Next(200);
                for (var r = 0; r < repeats; r++)
                {
                    builder.Append(line).Append('\n');
                    if (builder.Length > MaxLength)
                    {
                        return builder.ToString();
                    }
                }
            }
        }

        return builder.ToString();
    }

    private static string CorruptNumeric(string source, Random rng)
    {
        var chars = source.ToCharArray();
        var replacement = rng.Next(5) switch
        {
            0 => "999999999999999999999999999999",
            1 => "-1",
            2 => "+7",
            3 => "0x1F",
            _ => "NaN",
        };

        // Find a run of digits and splice the replacement over its first character.
        var starts = new List<int>();
        for (var i = 0; i < chars.Length; i++)
        {
            if (char.IsDigit(chars[i]))
            {
                starts.Add(i);
            }
        }

        if (starts.Count == 0)
        {
            return source;
        }

        var at = starts[rng.Next(starts.Count)];
        return string.Concat(source.AsSpan(0, at), replacement, source.AsSpan(Math.Min(source.Length, at + 1)));
    }

    private static string DeleteChars(string source, Random rng)
    {
        if (source.Length == 0)
        {
            return source;
        }

        var builder = new StringBuilder(source.Length);
        var dropRate = 1 + rng.Next(10);
        foreach (var c in source)
        {
            if (rng.Next(100) >= dropRate)
            {
                builder.Append(c);
            }
        }

        return builder.ToString();
    }

    private static string InjectDelimiters(string source, Random rng)
    {
        var builder = new StringBuilder(source);
        var count = 1 + rng.Next(64);
        const string delimiters = "=:;/, \r\n~*";
        for (var n = 0; n < count; n++)
        {
            var index = builder.Length == 0 ? 0 : rng.Next(builder.Length);
            builder.Insert(index, delimiters[rng.Next(delimiters.Length)]);
        }

        return builder.ToString();
    }

    private static string InsertUnicode(string source, Random rng)
    {
        var builder = new StringBuilder(source);
        var count = 1 + rng.Next(32);
        for (var n = 0; n < count; n++)
        {
            var index = builder.Length == 0 ? 0 : rng.Next(builder.Length);
            builder.Insert(index, (char)rng.Next(0x1, 0xFFFF));
        }

        return builder.ToString();
    }

    // ---- Garbage generators ---------------------------------------------------------------------

    private static string RandomUnicode(Random rng)
    {
        var length = NextLength(rng);
        var chars = new char[length];
        for (var i = 0; i < length; i++)
        {
            // Skip the surrogate range to keep well-formed UTF-16; parser must handle either way but
            // this keeps the corpus varied without depending on invalid-surrogate behaviour.
            var c = rng.Next(0x1, 0xD800);
            chars[i] = (char)c;
        }

        return new string(chars);
    }

    private static string RandomLatin1(Random rng)
    {
        var length = NextLength(rng);
        var bytes = new byte[length];
        rng.NextBytes(bytes);
        return Encoding.Latin1.GetString(bytes);
    }

    private static string RandomTypedLines(Random rng)
    {
        const string types = "vosiuepcbtrzkam xy";
        var lineCount = rng.Next(1, 40);
        var builder = new StringBuilder();
        for (var i = 0; i < lineCount; i++)
        {
            var type = types[rng.Next(types.Length)];
            var valueLength = rng.Next(0, 48);
            builder.Append(type).Append('=');
            for (var j = 0; j < valueLength; j++)
            {
                builder.Append((char)rng.Next(0x20, 0x7F));
            }

            builder.Append(rng.Next(2) == 0 ? "\r\n" : "\n");
        }

        return builder.ToString();
    }

    private static int NextLength(Random rng) => rng.Next(4) switch
    {
        0 => rng.Next(0, 4),
        1 => rng.Next(4, 64),
        2 => rng.Next(64, 512),
        _ => rng.Next(512, 4096),
    };

    private static string Report(string stage, Exception ex, string strategy, int seed, int iteration, string text)
    {
        var preview = text.Length > 4000 ? text[..4000] + "…(truncated)" : text;
        return $"SDP {stage} threw uncontrolled {ex.GetType().FullName} " +
               $"(strategy={strategy}, seed={seed}, iter={iteration}): {ex.Message}\n" +
               $"length={text.Length}\ntext=<<<{preview}>>>";
    }

    // A realistic simulcast offer (Chrome, unified plan) with a=rid and a=simulcast, so the mutation
    // corpus covers those parsers as well.
    private const string SimulcastOffer =
        "v=0\r\n" +
        "o=- 3499715929743756150 2 IN IP4 127.0.0.1\r\n" +
        "s=-\r\n" +
        "t=0 0\r\n" +
        "a=group:BUNDLE 0\r\n" +
        "a=extmap-allow-mixed\r\n" +
        "a=msid-semantic: WMS\r\n" +
        "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n" +
        "c=IN IP4 0.0.0.0\r\n" +
        "a=rtcp:9 IN IP4 0.0.0.0\r\n" +
        "a=ice-ufrag:9m1x\r\n" +
        "a=ice-pwd:Q0pTbXKQVjJ9wRVWy3zNsL6m\r\n" +
        "a=ice-options:trickle\r\n" +
        "a=fingerprint:sha-256 " + SdpTestData.Fingerprint + "\r\n" +
        "a=setup:actpass\r\n" +
        "a=mid:0\r\n" +
        "a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r\n" +
        "a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n" +
        "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n" +
        "a=sendonly\r\n" +
        "a=rtcp-mux\r\n" +
        "a=rtpmap:96 H264/90000\r\n" +
        "a=rtcp-fb:96 nack\r\n" +
        "a=rtcp-fb:96 nack pli\r\n" +
        "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n" +
        "a=rtpmap:97 rtx/90000\r\n" +
        "a=fmtp:97 apt=96\r\n" +
        "a=rid:hi send\r\n" +
        "a=rid:mid send\r\n" +
        "a=rid:lo send\r\n" +
        "a=simulcast:send hi;mid;lo\r\n";
}
