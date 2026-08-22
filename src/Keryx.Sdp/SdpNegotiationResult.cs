namespace Keryx.Sdp;

/// <summary>The result of applying an answer to an offer: one entry per m-section, in JSEP order.</summary>
public sealed class SdpNegotiationResult
{
    internal SdpNegotiationResult(
        SessionDescription offer,
        SessionDescription answer,
        IReadOnlyList<NegotiatedMedia> media,
        IReadOnlyList<string> bundleMids)
    {
        Offer = offer;
        Answer = answer;
        Media = media;
        BundleMids = bundleMids;
    }

    /// <summary>The offer that was sent.</summary>
    public SessionDescription Offer { get; }

    /// <summary>The answer that was received.</summary>
    public SessionDescription Answer { get; }

    /// <summary>One entry per m-section, in offer order.</summary>
    public IReadOnlyList<NegotiatedMedia> Media { get; }

    /// <summary>The mids the answer agreed to bundle, empty when the answerer declined BUNDLE.</summary>
    public IReadOnlyList<string> BundleMids { get; }

    /// <summary>True when the answer kept every offered m-section on one bundled transport.</summary>
    public bool IsBundled => BundleMids.Count > 0 && BundleMids.Count == Media.Count(static m => !m.IsRejected);

    /// <summary>The m-sections the answerer did not reject.</summary>
    public IEnumerable<NegotiatedMedia> ActiveMedia => Media.Where(static m => !m.IsRejected);

    /// <summary>Looks up a negotiated m-section by mid.</summary>
    /// <param name="mid">The mid, compared ordinally.</param>
    /// <returns>The entry, or <see langword="null"/> when no section carries that mid.</returns>
    public NegotiatedMedia? GetByMid(string mid)
    {
        ArgumentNullException.ThrowIfNull(mid);
        return Media.FirstOrDefault(m => string.Equals(m.Mid, mid, StringComparison.Ordinal));
    }

    /// <summary>Looks up the first negotiated m-section of a media type.</summary>
    /// <param name="mediaType">Media type, for example <c>video</c>, compared ordinally.</param>
    /// <returns>The entry, or <see langword="null"/> when the session has no such section.</returns>
    public NegotiatedMedia? GetByMediaType(string mediaType)
    {
        ArgumentNullException.ThrowIfNull(mediaType);
        return Media.FirstOrDefault(m => string.Equals(m.MediaType, mediaType, StringComparison.Ordinal));
    }
}
