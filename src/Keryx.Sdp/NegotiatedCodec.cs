namespace Keryx.Sdp;

/// <summary>
/// One codec both sides kept: the payload type, its rtpmap, its fmtp string as written by the
/// answerer, and the feedback capabilities the answerer confirmed.
/// </summary>
/// <param name="PayloadType">The negotiated RTP payload type.</param>
/// <param name="RtpMap">The rtpmap from the answer, or from the offer when the answer omitted it.</param>
/// <param name="Fmtp">
/// The raw fmtp parameter string from the answer, or from the offer when the answer omitted it.
/// Callers match on this to pick, for example, the H.264 payload type carrying
/// <c>packetization-mode=1</c> and <c>profile-level-id=42e01f</c>.
/// </param>
/// <param name="Feedback">Feedback capabilities the answer advertises for this payload type.</param>
public sealed record NegotiatedCodec(
    int PayloadType,
    RtpMap RtpMap,
    string? Fmtp,
    IReadOnlyList<RtcpFeedback> Feedback)
{
    /// <summary>Encoding name from <see cref="RtpMap"/>, for example <c>H264</c>.</summary>
    public string EncodingName => RtpMap.EncodingName;

    /// <summary>Clock rate from <see cref="RtpMap"/>.</summary>
    public int ClockRate => RtpMap.ClockRate;

    /// <summary>The fmtp string split on <c>;</c> into key/value pairs.</summary>
    /// <returns>An ordinal lookup; empty when there is no fmtp.</returns>
    public IReadOnlyDictionary<string, string> GetFmtpParameters() => FmtpParameters.Parse(Fmtp);

    /// <summary>True when the encoding name matches, ignoring case as SDP encoding names do.</summary>
    /// <param name="encodingName">Encoding name to compare, for example <c>opus</c>.</param>
    /// <returns>True on a match.</returns>
    public bool Is(string encodingName) =>
        string.Equals(RtpMap.EncodingName, encodingName, StringComparison.OrdinalIgnoreCase);

    /// <summary>True when the fmtp string carries <paramref name="key"/> equal to <paramref name="value"/>.</summary>
    /// <param name="key">Parameter name, compared ordinally.</param>
    /// <param name="value">Expected value, compared case-insensitively.</param>
    /// <returns>True on a match.</returns>
    public bool HasFmtp(string key, string value) => FmtpParameters.Matches(Fmtp, key, value);

    /// <summary>True when the answer advertises <paramref name="feedback"/> for this payload type.</summary>
    /// <param name="feedback">The capability to look for.</param>
    /// <returns>True when present.</returns>
    public bool SupportsFeedback(RtcpFeedback feedback)
    {
        ArgumentNullException.ThrowIfNull(feedback);
        return Feedback.Contains(feedback);
    }
}
