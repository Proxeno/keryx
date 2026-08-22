using System.Globalization;

namespace Keryx.Sdp;

/// <summary>
/// Builds a JSEP offer in the shape browsers expect: BUNDLE group, one transport block per
/// m-section, and per-codec rtpmap/rtcp-fb/fmtp lines in Chrome's order.
/// </summary>
/// <remarks>
/// Everything the offer contains comes from the properties set on this builder and on each
/// <see cref="SdpMediaOffer"/>; the builder hardcodes only the placeholders JSEP mandates
/// (<c>c=IN IP4 0.0.0.0</c>, port 9, <c>t=0 0</c>).
/// </remarks>
public sealed class SdpOfferBuilder
{
    /// <summary><c>o=</c> username field. WebRTC always uses <c>-</c>.</summary>
    public string OriginUsername { get; set; } = "-";

    /// <summary><c>o=</c> session id. Defaults to a fresh random 63-bit value.</summary>
    public string SessionId { get; set; } = SdpOrigin.NewSessionId();

    /// <summary><c>o=</c> session version. Chrome starts at 2 and increments per renegotiation.</summary>
    public string SessionVersion { get; set; } = "2";

    /// <summary><c>s=</c> session name. WebRTC always uses <c>-</c>.</summary>
    public string SessionName { get; set; } = "-";

    /// <summary>ICE credentials applied to every m-section that does not override them.</summary>
    public SdpIceCredentials? IceCredentials { get; set; }

    /// <summary>DTLS certificate fingerprint applied to every m-section that does not override it.</summary>
    public SdpFingerprint? Fingerprint { get; set; }

    /// <summary>DTLS role applied to every m-section that does not override it. An offer uses <c>actpass</c>.</summary>
    public SdpSetupRole Setup { get; set; } = SdpSetupRole.ActPass;

    /// <summary>Emit <c>a=ice-options:trickle</c> on every m-section.</summary>
    public bool TrickleIce { get; set; } = true;

    /// <summary>Whether to emit <c>a=group:BUNDLE</c>.</summary>
    public SdpBundlePolicy BundlePolicy { get; set; } = SdpBundlePolicy.MaxBundle;

    /// <summary>Emit the session-level <c>a=extmap-allow-mixed</c> flag Chrome sends.</summary>
    public bool ExtMapAllowMixed { get; set; }

    /// <summary>Canonical name used for <c>a=ssrc:&lt;ssrc&gt; cname:</c> unless a section overrides it.</summary>
    public string? Cname { get; set; }

    /// <summary>
    /// MediaStream identifier used for <c>a=msid</c> and <c>a=msid-semantic: WMS</c> unless a section
    /// overrides it.
    /// </summary>
    public string? StreamId { get; set; }

    /// <summary>The m-sections to emit, in order. JSEP fixes this order for the lifetime of the session.</summary>
    public IList<SdpMediaOffer> Media { get; } = new List<SdpMediaOffer>();

    /// <summary>Appends an m-section.</summary>
    /// <param name="media">The m-section description.</param>
    /// <returns>This instance.</returns>
    public SdpOfferBuilder AddMedia(SdpMediaOffer media)
    {
        ArgumentNullException.ThrowIfNull(media);
        Media.Add(media);
        return this;
    }

    /// <summary>Appends a send-only audio m-section.</summary>
    /// <param name="mid">The <c>a=mid</c> value.</param>
    /// <param name="codecs">Audio codecs in preference order.</param>
    /// <returns>This instance.</returns>
    public SdpOfferBuilder AddAudio(string mid, params SdpCodec[] codecs) =>
        AddMedia(SdpMediaOffer.Audio(mid, codecs));

    /// <summary>Appends a send-only video m-section.</summary>
    /// <param name="mid">The <c>a=mid</c> value.</param>
    /// <param name="codecs">Video codecs in preference order.</param>
    /// <returns>This instance.</returns>
    public SdpOfferBuilder AddVideo(string mid, params SdpCodec[] codecs) =>
        AddMedia(SdpMediaOffer.Video(mid, codecs));

    /// <summary>Appends the SCTP data channel m-section.</summary>
    /// <param name="mid">The <c>a=mid</c> value.</param>
    /// <param name="sctpPort">The <c>a=sctp-port</c> value.</param>
    /// <param name="maxMessageSize">The <c>a=max-message-size</c> value in bytes.</param>
    /// <returns>This instance.</returns>
    public SdpOfferBuilder AddDataChannel(string mid, int sctpPort = 5000, int maxMessageSize = 262144) =>
        AddMedia(SdpMediaOffer.Application(mid, sctpPort, maxMessageSize));

    /// <summary>Produces the offer.</summary>
    /// <returns>A session description ready to serialize with <see cref="SessionDescription.ToSdpString"/>.</returns>
    /// <exception cref="SdpException">
    /// No m-sections were added, mids are duplicated, or an m-section has neither its own nor a
    /// session-level ICE credential or fingerprint.
    /// </exception>
    public SessionDescription Build()
    {
        if (Media.Count == 0)
        {
            throw new SdpException("An offer needs at least one m-section.");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var media in Media)
        {
            if (!seen.Add(media.Mid))
            {
                throw new SdpException($"Duplicate mid '{media.Mid}': every m-section needs a unique mid.");
            }
        }

        var session = new SessionDescription
        {
            Version = 0,
            Origin = new SdpOrigin(OriginUsername, SessionId, SessionVersion, "IN", "IP4", "127.0.0.1"),
            SessionName = SessionName,
        };
        session.Timings.Add(new SdpTiming("0", "0"));

        if (BundlePolicy == SdpBundlePolicy.MaxBundle)
        {
            session.SetBundleGroup(Media.Select(static m => m.Mid));
        }

        if (ExtMapAllowMixed)
        {
            session.ExtMapAllowMixed = true;
        }

        if (StreamId is { } streamId)
        {
            session.SetWmsStreamIds(streamId);
        }
        else
        {
            session.SetWmsStreamIds();
        }

        foreach (var media in Media)
        {
            session.MediaDescriptions.Add(BuildMedia(media));
        }

        return session;
    }

    private MediaDescription BuildMedia(SdpMediaOffer offer)
    {
        var ice = offer.IceCredentials ?? IceCredentials
            ?? throw new SdpException($"m-section '{offer.Mid}' has no ICE credentials.");
        var fingerprint = offer.Fingerprint ?? Fingerprint
            ?? throw new SdpException($"m-section '{offer.Mid}' has no DTLS fingerprint.");

        var media = new MediaDescription
        {
            Media = offer.MediaType,
            Port = offer.Port,
            Protocol = offer.Protocol,
            Connection = SdpConnection.WebRtcPlaceholder,
        };

        if (offer.Codecs.Count > 0)
        {
            foreach (var codec in offer.Codecs)
            {
                media.Formats.Add(codec.PayloadType.ToString(CultureInfo.InvariantCulture));
            }
        }
        else if (string.Equals(offer.MediaType, "application", StringComparison.Ordinal))
        {
            media.Formats.Add(SdpMediaOffer.DataChannelFormat);
        }

        if (offer.IncludeRtcpAttribute)
        {
            media.AddAttribute(SdpAttributeNames.Rtcp, "9 IN IP4 0.0.0.0");
        }

        media.AddAttribute(SdpAttributeNames.IceUfrag, ice.UsernameFragment);
        media.AddAttribute(SdpAttributeNames.IcePwd, ice.Password);
        if (TrickleIce)
        {
            media.AddAttribute(SdpAttributeNames.IceOptions, "trickle");
        }

        media.AddAttribute(SdpAttributeNames.Fingerprint, fingerprint.ToAttributeValue());
        media.AddAttribute(SdpAttributeNames.Setup, (offer.Setup ?? Setup).ToAttributeValue());
        media.AddAttribute(SdpAttributeNames.Mid, offer.Mid);

        foreach (var extMap in offer.HeaderExtensions)
        {
            media.AddExtMap(extMap);
        }

        if (offer.Direction is { } direction)
        {
            media.AddAttribute(direction.ToAttributeName());
        }

        var streamId = offer.StreamId ?? StreamId;
        if (streamId is not null && offer.TrackId is { } trackId)
        {
            media.AddAttribute(SdpAttributeNames.Msid, new SdpMsid(streamId, trackId).ToAttributeValue());
        }

        if (offer.RtcpMux)
        {
            media.AddAttribute(SdpAttributeNames.RtcpMux);
        }

        if (offer.RtcpReducedSize)
        {
            media.AddAttribute(SdpAttributeNames.RtcpReducedSize);
        }

        foreach (var codec in offer.Codecs)
        {
            media.AddAttribute(SdpAttributeNames.RtpMap, codec.ToRtpMap().ToAttributeValue());
            foreach (var feedback in codec.Feedback)
            {
                media.AddAttribute(
                    SdpAttributeNames.RtcpFeedback,
                    new RtcpFeedbackEntry(codec.PayloadType, feedback).ToAttributeValue());
            }

            if (codec.Fmtp is { } fmtp)
            {
                media.AddAttribute(
                    SdpAttributeNames.Fmtp,
                    string.Create(CultureInfo.InvariantCulture, $"{codec.PayloadType} {fmtp}"));
            }
        }

        if (offer.SctpPort is { } sctpPort)
        {
            media.AddAttribute(SdpAttributeNames.SctpPort, sctpPort.ToString(CultureInfo.InvariantCulture));
        }

        if (offer.MaxMessageSize is { } maxMessageSize)
        {
            media.AddAttribute(
                SdpAttributeNames.MaxMessageSize,
                maxMessageSize.ToString(CultureInfo.InvariantCulture));
        }

        foreach (var group in offer.SsrcGroups)
        {
            media.AddAttribute(SdpAttributeNames.SsrcGroup, group.ToAttributeValue());
        }

        var cname = offer.Cname ?? Cname;
        foreach (var ssrc in offer.Ssrcs)
        {
            if (cname is not null)
            {
                media.AddSsrcAttribute(ssrc, SdpAttributeNames.Cname, cname);
            }

            if (streamId is not null && offer.TrackId is { } track)
            {
                media.AddSsrcAttribute(
                    ssrc,
                    SdpAttributeNames.Msid,
                    new SdpMsid(streamId, track).ToAttributeValue());
            }
        }

        foreach (var attribute in offer.ExtraAttributes)
        {
            media.Attributes.Add(attribute);
        }

        return media;
    }
}
