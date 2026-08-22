namespace Keryx.Sdp;

/// <summary>
/// What one m-section of an answer settled on, paired with the offer's m-section at the same index.
/// </summary>
public sealed class NegotiatedMedia
{
    internal NegotiatedMedia(int index, MediaDescription offered, MediaDescription answered)
    {
        Index = index;
        Offered = offered;
        Answered = answered;
    }

    /// <summary>Zero-based m-section index, identical in offer and answer per JSEP.</summary>
    public int Index { get; }

    /// <summary>The offer's m-section.</summary>
    public MediaDescription Offered { get; }

    /// <summary>The answer's m-section.</summary>
    public MediaDescription Answered { get; }

    /// <summary>The mid, taken from the answer and falling back to the offer.</summary>
    public string? Mid => Answered.Mid ?? Offered.Mid;

    /// <summary>Media type, for example <c>audio</c>.</summary>
    public string MediaType => Answered.Media;

    /// <summary>True when the answerer rejected the section by answering with port 0.</summary>
    public bool IsRejected => Answered.IsRejected;

    /// <summary>The direction the offerer asked for.</summary>
    public MediaDirection OfferedDirection => Offered.DirectionOrDefault;

    /// <summary>The direction the answerer wrote, from the answerer's point of view.</summary>
    public MediaDirection AnsweredDirection => Answered.DirectionOrDefault;

    /// <summary>
    /// The intersection of offer and answer, expressed from the <em>offerer's</em> point of view. A
    /// rejected section is always <see cref="MediaDirection.Inactive"/>.
    /// </summary>
    public MediaDirection Direction => IsRejected
        ? MediaDirection.Inactive
        : SdpDirection.Negotiate(OfferedDirection, AnsweredDirection);

    /// <summary>True when the offerer may transmit media on this section.</summary>
    public bool CanSend => Direction.Sends();

    /// <summary>True when the offerer may receive media on this section.</summary>
    public bool CanReceive => Direction.Receives();

    /// <summary>
    /// Payload types both sides kept, ordered by the offer's preference. Empty for a rejected or
    /// non-RTP section.
    /// </summary>
    public IReadOnlyList<NegotiatedCodec> Codecs { get; internal set; } = [];

    /// <summary>The remote <c>a=ice-ufrag</c>, falling back to the answer's session level.</summary>
    public string? IceUfrag { get; internal set; }

    /// <summary>The remote <c>a=ice-pwd</c>, falling back to the answer's session level.</summary>
    public string? IcePwd { get; internal set; }

    /// <summary>The remote <c>a=ice-options</c> tokens.</summary>
    public IReadOnlyList<string> IceOptions { get; internal set; } = [];

    /// <summary>True when the remote advertised <c>trickle</c> in <c>a=ice-options</c>.</summary>
    public bool SupportsTrickleIce => IceOptions.Contains("trickle", StringComparer.Ordinal);

    /// <summary>The remote DTLS fingerprint, falling back to the answer's session level.</summary>
    public SdpFingerprint? Fingerprint { get; internal set; }

    /// <summary>
    /// The remote DTLS role. An answer must pick <c>active</c> or <c>passive</c>; see
    /// <see cref="LocalSetup"/> for the role that leaves the local endpoint.
    /// </summary>
    public SdpSetupRole? Setup { get; internal set; }

    /// <summary>The DTLS role the local endpoint must take, complementary to <see cref="Setup"/>.</summary>
    public SdpSetupRole? LocalSetup => Setup?.Complement();

    /// <summary>True when the answer confirmed <c>a=rtcp-mux</c>.</summary>
    public bool RtcpMux => Answered.RtcpMux;

    /// <summary>True when the answer confirmed <c>a=rtcp-rsize</c>.</summary>
    public bool RtcpReducedSize => Answered.RtcpReducedSize;

    /// <summary>Header extensions the answer kept.</summary>
    public IReadOnlyList<SdpExtMap> HeaderExtensions { get; internal set; } = [];

    /// <summary>Synchronisation sources the answer declares, empty for a receive-only remote.</summary>
    public IReadOnlyList<uint> Ssrcs { get; internal set; } = [];

    /// <summary>The canonical name of the answer's first source, when it declares one.</summary>
    public string? Cname { get; internal set; }

    /// <summary>The answer's <c>a=msid</c>, when present.</summary>
    public SdpMsid? Msid { get; internal set; }

    /// <summary>The answer's <c>a=sctp-port</c>, for the data channel section.</summary>
    public int? SctpPort { get; internal set; }

    /// <summary>The answer's <c>a=max-message-size</c>, for the data channel section.</summary>
    public int? MaxMessageSize { get; internal set; }

    /// <summary>
    /// Raw <c>a=candidate</c> values from the answer, in document order. A trickling browser usually
    /// sends none in the answer itself.
    /// </summary>
    public IReadOnlyList<string> Candidates { get; internal set; } = [];

    /// <summary>True when the answer carried <c>a=end-of-candidates</c>.</summary>
    public bool EndOfCandidates => Answered.EndOfCandidates;

    /// <summary>Finds a negotiated codec by encoding name.</summary>
    /// <param name="encodingName">Encoding name, compared case-insensitively.</param>
    /// <returns>The first match in offer preference order, or <see langword="null"/>.</returns>
    public NegotiatedCodec? FindCodec(string encodingName)
    {
        ArgumentNullException.ThrowIfNull(encodingName);
        return Codecs.FirstOrDefault(c => c.Is(encodingName));
    }

    /// <summary>
    /// Finds the RFC 4588 retransmission codec that repairs <paramref name="payloadType"/>: an
    /// <c>rtx</c> entry whose <c>apt</c> names it.
    /// </summary>
    /// <param name="payloadType">The media payload type whose repair stream is wanted.</param>
    /// <returns>
    /// The rtx codec, or <see langword="null"/> when the answerer dropped it — in which case the
    /// offerer must not retransmit, whatever <c>a=rtcp-fb</c> the answer still carries.
    /// </returns>
    public NegotiatedCodec? FindRtxCodec(int payloadType) =>
        Codecs.FirstOrDefault(c => c.IsRtx && c.GetAssociatedPayloadType() == payloadType);

    /// <summary>Finds a negotiated codec by encoding name and one required fmtp parameter.</summary>
    /// <param name="encodingName">Encoding name, compared case-insensitively.</param>
    /// <param name="fmtpKey">fmtp parameter name, compared ordinally.</param>
    /// <param name="fmtpValue">Required fmtp value, compared case-insensitively.</param>
    /// <returns>The first match in offer preference order, or <see langword="null"/>.</returns>
    public NegotiatedCodec? FindCodec(string encodingName, string fmtpKey, string fmtpValue)
    {
        ArgumentNullException.ThrowIfNull(encodingName);
        return Codecs.FirstOrDefault(c => c.Is(encodingName) && c.HasFmtp(fmtpKey, fmtpValue));
    }
}
