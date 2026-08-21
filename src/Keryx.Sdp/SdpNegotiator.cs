using System.Globalization;

namespace Keryx.Sdp;

/// <summary>
/// Reads a JSEP answer against the offer that produced it: validates the m-section alignment JSEP
/// requires, then reports per-mid what the remote agreed to.
/// </summary>
public static class SdpNegotiator
{
    /// <summary>
    /// Checks the structural rules JSEP places on an answer: the same number of m-sections, in the
    /// same order, with the same media types, protocols and mids, and a BUNDLE group drawn only from
    /// offered mids.
    /// </summary>
    /// <param name="offer">The offer that was sent.</param>
    /// <param name="answer">The answer that was received.</param>
    /// <returns>The outcome, listing every violation found.</returns>
    public static SdpValidationResult Validate(SessionDescription offer, SessionDescription answer)
    {
        ArgumentNullException.ThrowIfNull(offer);
        ArgumentNullException.ThrowIfNull(answer);

        var result = new SdpValidationResult();
        if (offer.MediaDescriptions.Count != answer.MediaDescriptions.Count)
        {
            result.Add(string.Create(
                CultureInfo.InvariantCulture,
                $"answer has {answer.MediaDescriptions.Count} m-section(s), offer has {offer.MediaDescriptions.Count}"));
            return result;
        }

        for (var i = 0; i < offer.MediaDescriptions.Count; i++)
        {
            var offered = offer.MediaDescriptions[i];
            var answered = answer.MediaDescriptions[i];

            if (!string.Equals(offered.Media, answered.Media, StringComparison.Ordinal))
            {
                result.Add(string.Create(
                    CultureInfo.InvariantCulture,
                    $"m-section {i}: answer media type '{answered.Media}' does not match offer '{offered.Media}'"));
            }

            if (!string.Equals(offered.Protocol, answered.Protocol, StringComparison.Ordinal))
            {
                result.Add(string.Create(
                    CultureInfo.InvariantCulture,
                    $"m-section {i}: answer protocol '{answered.Protocol}' does not match offer '{offered.Protocol}'"));
            }

            if (offered.Mid is { } offeredMid &&
                answered.Mid is { } answeredMid &&
                !string.Equals(offeredMid, answeredMid, StringComparison.Ordinal))
            {
                result.Add(string.Create(
                    CultureInfo.InvariantCulture,
                    $"m-section {i}: answer mid '{answeredMid}' does not match offer mid '{offeredMid}'"));
            }
        }

        var offeredMids = new HashSet<string>(
            offer.MediaDescriptions.Select(static m => m.Mid).OfType<string>(),
            StringComparer.Ordinal);
        foreach (var mid in answer.GetBundleGroup())
        {
            if (!offeredMids.Contains(mid))
            {
                result.Add($"answer BUNDLE group names mid '{mid}', which the offer does not contain");
            }
        }

        return result;
    }

    /// <summary>Validates the answer and then interprets it.</summary>
    /// <param name="offer">The offer that was sent.</param>
    /// <param name="answer">The answer that was received.</param>
    /// <returns>The per-m-section negotiation outcome.</returns>
    /// <exception cref="SdpException">The answer violates a JSEP alignment rule.</exception>
    public static SdpNegotiationResult Negotiate(SessionDescription offer, SessionDescription answer)
    {
        Validate(offer, answer).ThrowIfInvalid();
        return Interpret(offer, answer);
    }

    /// <summary>
    /// Interprets the answer without validating it. Use when the caller has already validated, or
    /// deliberately wants a best-effort read of a non-conforming answer.
    /// </summary>
    /// <param name="offer">The offer that was sent.</param>
    /// <param name="answer">The answer that was received.</param>
    /// <returns>The per-m-section negotiation outcome, covering the m-sections both documents share.</returns>
    public static SdpNegotiationResult Interpret(SessionDescription offer, SessionDescription answer)
    {
        ArgumentNullException.ThrowIfNull(offer);
        ArgumentNullException.ThrowIfNull(answer);

        var count = Math.Min(offer.MediaDescriptions.Count, answer.MediaDescriptions.Count);
        var media = new List<NegotiatedMedia>(count);
        for (var i = 0; i < count; i++)
        {
            media.Add(Interpret(i, offer.MediaDescriptions[i], answer.MediaDescriptions[i], answer));
        }

        return new SdpNegotiationResult(offer, answer, media, answer.GetBundleGroup());
    }

    private static NegotiatedMedia Interpret(
        int index,
        MediaDescription offered,
        MediaDescription answered,
        SessionDescription answerSession)
    {
        var result = new NegotiatedMedia(index, offered, answered)
        {
            IceUfrag = answered.IceUfrag ?? answerSession.IceUfrag,
            IcePwd = answered.IcePwd ?? answerSession.IcePwd,
            IceOptions = answered.GetIceOptions().Count > 0
                ? answered.GetIceOptions()
                : answerSession.GetIceOptions(),
            Fingerprint = answered.Fingerprint ?? answerSession.Fingerprint,
            Setup = answered.Setup ?? answerSession.Setup,
            HeaderExtensions = answered.GetExtMaps(),
            Ssrcs = answered.GetSsrcs(),
            Msid = answered.Msid,
            SctpPort = answered.SctpPort,
            MaxMessageSize = answered.MaxMessageSize,
            Candidates = answered.GetCandidates(),
        };

        var ssrcs = result.Ssrcs;
        result.Cname = ssrcs.Count > 0 ? answered.GetSsrcCname(ssrcs[0]) : null;
        result.Codecs = answered.IsRejected ? [] : IntersectCodecs(offered, answered);
        return result;
    }

    private static IReadOnlyList<NegotiatedCodec> IntersectCodecs(MediaDescription offered, MediaDescription answered)
    {
        var accepted = new HashSet<int>(answered.GetPayloadTypes());
        if (accepted.Count == 0)
        {
            return [];
        }

        var result = new List<NegotiatedCodec>();
        foreach (var payloadType in offered.GetPayloadTypes())
        {
            if (!accepted.Contains(payloadType))
            {
                continue;
            }

            var rtpMap = answered.GetRtpMap(payloadType) ?? offered.GetRtpMap(payloadType);
            if (rtpMap is null)
            {
                continue;
            }

            var fmtp = answered.GetFmtp(payloadType) ?? offered.GetFmtp(payloadType);
            var feedback = answered.GetRtcpFeedback(payloadType);
            result.Add(new NegotiatedCodec(payloadType, rtpMap, fmtp, feedback));
        }

        return result;
    }
}
