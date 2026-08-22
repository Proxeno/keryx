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

    /// <summary>
    /// Builds the simulcast parts of an answer to one offered m-section: the <c>a=simulcast</c> line
    /// with its directions reversed (RFC 8853 §5.2), the <c>a=rid</c> declarations reversed with their
    /// restrictions kept verbatim, and the RID / repaired-RID / MID <c>a=extmap</c>s echoed from the
    /// offer. Never throws.
    /// </summary>
    /// <param name="offered">The offered m-section.</param>
    /// <param name="acceptRid">
    /// A capability predicate deciding whether the answerer keeps an offered RID, by RID id. An
    /// answerer MAY remove offered RIDs it cannot handle (RFC 8853 §5.2); this is the one
    /// selection-shaped decision made here and it is a capability decision (codec/resolution support),
    /// not a per-viewer bandwidth decision. <see langword="null"/> keeps every offered RID.
    /// </param>
    /// <returns>
    /// The simulcast answer parts, or <see langword="null"/> when the section carries no
    /// <c>a=simulcast</c> line (it is not a simulcast section) or every offered RID was pruned.
    /// </returns>
    public static SimulcastAnswer? AnswerSimulcast(MediaDescription offered, Func<string, bool>? acceptRid = null)
    {
        ArgumentNullException.ThrowIfNull(offered);

        var offeredSimulcast = offered.Simulcast;
        if (offeredSimulcast is null)
        {
            return null;
        }

        acceptRid ??= static _ => true;

        // The offered a=rid declarations, indexed by id, so kept RIDs preserve their restrictions and
        // an alternative referencing an undeclared RID is dropped rather than echoed bare.
        var offeredRids = new Dictionary<string, SdpRid>(StringComparer.Ordinal);
        foreach (var rid in offered.GetRids())
        {
            offeredRids.TryAdd(rid.Id, rid);
        }

        bool Keep(string id) => offeredRids.ContainsKey(id) && acceptRid(id);

        // Reverse directions (offered send becomes the answerer's recv, and vice versa) and prune the
        // RIDs the answerer will not accept from each stream's alternative list.
        var answerSend = PruneStreams(offeredSimulcast.Recv, Keep);
        var answerRecv = PruneStreams(offeredSimulcast.Send, Keep);
        if (answerSend.Count == 0 && answerRecv.Count == 0)
        {
            return null;
        }

        // Echo an a=rid line for every RID that survived, in offered document order, with its direction
        // reversed and its restrictions carried through untouched.
        var kept = CollectKeptIds(answerSend, answerRecv);
        var answerRids = new List<SdpRid>();
        foreach (var rid in offered.GetRids())
        {
            if (kept.Contains(rid.Id) && !answerRids.Exists(r => string.Equals(r.Id, rid.Id, StringComparison.Ordinal)))
            {
                var direction = rid.Direction == RidDirection.Send ? RidDirection.Recv : RidDirection.Send;
                answerRids.Add(new SdpRid(rid.Id, direction, rid.Restrictions));
            }
        }

        var extensions = new List<SdpExtMap>();
        foreach (var extMap in offered.GetExtMaps())
        {
            if (IsStreamIdentifierExtension(extMap.Uri))
            {
                extensions.Add(new SdpExtMap(extMap.Id, extMap.Uri));
            }
        }

        return new SimulcastAnswer(new SdpSimulcast(answerSend, answerRecv), answerRids, extensions);
    }

    private static IReadOnlyList<SdpSimulcastStream> PruneStreams(
        IReadOnlyList<SdpSimulcastStream> streams,
        Func<string, bool> keep)
    {
        if (streams.Count == 0)
        {
            return Array.Empty<SdpSimulcastStream>();
        }

        var result = new List<SdpSimulcastStream>();
        foreach (var stream in streams)
        {
            var alternatives = new List<SdpSimulcastAlternative>();
            foreach (var alternative in stream.Alternatives)
            {
                if (keep(alternative.Id))
                {
                    alternatives.Add(alternative);
                }
            }

            if (alternatives.Count != 0)
            {
                result.Add(new SdpSimulcastStream(alternatives));
            }
        }

        return result;
    }

    private static HashSet<string> CollectKeptIds(
        IReadOnlyList<SdpSimulcastStream> send,
        IReadOnlyList<SdpSimulcastStream> recv)
    {
        var kept = new HashSet<string>(StringComparer.Ordinal);
        foreach (var streams in new[] { send, recv })
        {
            foreach (var stream in streams)
            {
                foreach (var alternative in stream.Alternatives)
                {
                    kept.Add(alternative.Id);
                }
            }
        }

        return kept;
    }

    private static bool IsStreamIdentifierExtension(string uri) =>
        string.Equals(uri, RtpHeaderExtensionUri.Rid, StringComparison.Ordinal)
        || string.Equals(uri, RtpHeaderExtensionUri.RepairedRid, StringComparison.Ordinal)
        || string.Equals(uri, RtpHeaderExtensionUri.Mid, StringComparison.Ordinal);

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
