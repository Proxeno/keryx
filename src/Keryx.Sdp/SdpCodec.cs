namespace Keryx.Sdp;

/// <summary>
/// One codec an m-section offers: its payload type, rtpmap fields, optional fmtp string and RTCP
/// feedback capabilities. Nothing about the shape is codec specific, so community codecs slot in
/// without changes to this library.
/// </summary>
public sealed class SdpCodec
{
    /// <summary>The encoding name RFC 4588 gives the retransmission payload format.</summary>
    public const string RtxEncodingName = "rtx";

    /// <summary>The fmtp parameter naming the payload type an rtx entry repairs (RFC 4588 §8.1).</summary>
    public const string AssociatedPayloadTypeParameter = "apt";

    /// <summary>Creates a codec entry.</summary>
    /// <param name="payloadType">RTP payload type to advertise.</param>
    /// <param name="encodingName">Encoding name for <c>a=rtpmap</c>, for example <c>H264</c>.</param>
    /// <param name="clockRate">RTP clock rate in Hz.</param>
    /// <param name="channels">Channel count; audio only, omitted from <c>a=rtpmap</c> when null.</param>
    public SdpCodec(int payloadType, string encodingName, int clockRate, int? channels = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(encodingName);
        PayloadType = payloadType;
        EncodingName = encodingName;
        ClockRate = clockRate;
        Channels = channels;
    }

    /// <summary>RTP payload type.</summary>
    public int PayloadType { get; set; }

    /// <summary>Encoding name written to <c>a=rtpmap</c>.</summary>
    public string EncodingName { get; set; }

    /// <summary>True when this entry is an RFC 4588 retransmission codec.</summary>
    public bool IsRtx => string.Equals(EncodingName, RtxEncodingName, StringComparison.OrdinalIgnoreCase);

    /// <summary>The payload type this entry repairs, read from the <c>apt</c> fmtp parameter.</summary>
    /// <returns>The associated payload type, or <see langword="null"/> when there is no usable <c>apt</c>.</returns>
    public int? GetAssociatedPayloadType() =>
        int.TryParse(
            FmtpParameters.GetValue(Fmtp, AssociatedPayloadTypeParameter),
            System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture,
            out var apt)
            ? apt
            : null;

    /// <summary>RTP clock rate in Hz.</summary>
    public int ClockRate { get; set; }

    /// <summary>Channel count, or <see langword="null"/> to omit it from <c>a=rtpmap</c>.</summary>
    public int? Channels { get; set; }

    /// <summary>Raw <c>a=fmtp</c> parameter string, or <see langword="null"/> to emit no fmtp line.</summary>
    public string? Fmtp { get; set; }

    /// <summary>
    /// RTCP feedback capabilities emitted as <c>a=rtcp-fb:&lt;pt&gt; ...</c>, in list order.
    /// </summary>
    /// <remarks>
    /// Bare <see cref="RtcpFeedback.Nack"/> is never added implicitly, because advertising it commits
    /// the sender to serving retransmissions. <see cref="H264"/> adds it, and a
    /// <c>PeerConnection</c> pairs it with an <see cref="Rtx"/> entry in the same m-section so the
    /// promise can be kept.
    /// </remarks>
    public IList<RtcpFeedback> Feedback { get; } = new List<RtcpFeedback>();

    /// <summary>Sets <see cref="Fmtp"/> and returns this codec, for fluent construction.</summary>
    /// <param name="parameters">Raw fmtp parameter string.</param>
    /// <returns>This instance.</returns>
    public SdpCodec WithFmtp(string parameters)
    {
        Fmtp = parameters;
        return this;
    }

    /// <summary>Appends feedback capabilities and returns this codec, for fluent construction.</summary>
    /// <param name="feedback">Capabilities to advertise.</param>
    /// <returns>This instance.</returns>
    public SdpCodec WithFeedback(params RtcpFeedback[] feedback)
    {
        ArgumentNullException.ThrowIfNull(feedback);
        foreach (var item in feedback)
        {
            Feedback.Add(item);
        }

        return this;
    }

    /// <summary>Projects this codec onto the <c>a=rtpmap</c> model type.</summary>
    /// <returns>The matching rtpmap entry.</returns>
    public RtpMap ToRtpMap() => new(PayloadType, EncodingName, ClockRate, Channels);

    /// <summary>
    /// Opus at 48 kHz stereo with Chrome's default fmtp (<c>minptime=10;useinbandfec=1</c>) and
    /// transport-wide congestion control feedback.
    /// </summary>
    /// <param name="payloadType">Payload type; Chrome uses 111.</param>
    /// <returns>The codec entry.</returns>
    public static SdpCodec Opus(int payloadType = 111) =>
        new SdpCodec(payloadType, "opus", 48000, 2)
            .WithFmtp("minptime=10;useinbandfec=1")
            .WithFeedback(RtcpFeedback.TransportCc);

    /// <summary>
    /// H.264 at 90 kHz with the constrained-baseline profile browsers accept, plus <c>nack</c>,
    /// <c>nack pli</c>, <c>ccm fir</c> and <c>transport-cc</c> feedback, in Chrome's order.
    /// </summary>
    /// <remarks>
    /// Bare <c>nack</c> promises retransmission, which Keryx serves over RTX (RFC 4588). Offer this
    /// codec together with a matching <see cref="Rtx"/> entry — a <c>PeerConnection</c> does that
    /// automatically — or clear <see cref="Feedback"/> of <see cref="RtcpFeedback.Nack"/> if the
    /// m-section will carry no repair stream.
    /// </remarks>
    /// <param name="payloadType">Payload type.</param>
    /// <param name="profileLevelId">H.264 profile-level-id; <c>42e01f</c> is constrained baseline 3.1.</param>
    /// <param name="packetizationMode">RFC 6184 packetization mode; 1 is non-interleaved.</param>
    /// <returns>The codec entry.</returns>
    public static SdpCodec H264(int payloadType = 96, string profileLevelId = "42e01f", int packetizationMode = 1)
    {
        ArgumentException.ThrowIfNullOrEmpty(profileLevelId);
        var fmtp = FmtpParameters.Format(
        [
            new KeyValuePair<string, string>("level-asymmetry-allowed", "1"),
            new KeyValuePair<string, string>(
                "packetization-mode",
                packetizationMode.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new KeyValuePair<string, string>("profile-level-id", profileLevelId),
        ]);

        return new SdpCodec(payloadType, "H264", 90000)
            .WithFmtp(fmtp)
            .WithFeedback(
                RtcpFeedback.Nack,
                RtcpFeedback.NackPli,
                RtcpFeedback.CcmFir,
                RtcpFeedback.TransportCc);
    }

    /// <summary>An RTX repair codec bound to <paramref name="associatedPayloadType"/> via <c>apt</c>.</summary>
    /// <param name="payloadType">Payload type of the RTX stream.</param>
    /// <param name="associatedPayloadType">Payload type being repaired.</param>
    /// <param name="clockRate">RTP clock rate, which RFC 4588 §8.1 requires to match the repaired codec.</param>
    /// <returns>The codec entry.</returns>
    /// <remarks>
    /// Renders as <c>a=rtpmap:&lt;pt&gt; rtx/&lt;clock&gt;</c> plus <c>a=fmtp:&lt;pt&gt; apt=&lt;apt&gt;</c>.
    /// The repair stream also needs its own SSRC, associated with the media SSRC through
    /// <c>a=ssrc-group:FID</c> (RFC 5576 §4.2).
    /// </remarks>
    public static SdpCodec Rtx(int payloadType, int associatedPayloadType, int clockRate = 90000) =>
        new SdpCodec(payloadType, "rtx", clockRate)
            .WithFmtp("apt=" + associatedPayloadType.ToString(System.Globalization.CultureInfo.InvariantCulture));
}
