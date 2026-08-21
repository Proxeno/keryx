using System.Globalization;

namespace Keryx.Sdp;

/// <summary>
/// One m-section: the <c>m=</c> line plus everything up to the next <c>m=</c> line.
/// </summary>
public sealed class MediaDescription : SdpSection
{
    /// <summary>Creates an empty <c>audio</c> m-section on port 9.</summary>
    public MediaDescription()
    {
    }

    /// <summary>Creates an m-section with the given <c>m=</c> line fields.</summary>
    /// <param name="media">Media type, for example <c>audio</c>.</param>
    /// <param name="port">Transport port; 9 for WebRTC, 0 to reject the section.</param>
    /// <param name="protocol">Transport protocol, for example <c>UDP/TLS/RTP/SAVPF</c>.</param>
    /// <param name="formats">Media format tokens: RTP payload types, or <c>webrtc-datachannel</c>.</param>
    public MediaDescription(string media, int port, string protocol, params string[] formats)
    {
        ArgumentNullException.ThrowIfNull(media);
        ArgumentNullException.ThrowIfNull(protocol);
        ArgumentNullException.ThrowIfNull(formats);
        Media = media;
        Port = port;
        Protocol = protocol;
        foreach (var format in formats)
        {
            Formats.Add(format);
        }
    }

    /// <summary>Media type: <c>audio</c>, <c>video</c> or <c>application</c>.</summary>
    public string Media { get; set; } = "audio";

    /// <summary>Transport port. WebRTC offers use the placeholder 9; 0 rejects the m-section.</summary>
    public int Port { get; set; } = 9;

    /// <summary>Optional <c>/&lt;count&gt;</c> suffix on the port field.</summary>
    public int? PortCount { get; set; }

    /// <summary>Transport protocol, for example <c>UDP/TLS/RTP/SAVPF</c> or <c>UDP/DTLS/SCTP</c>.</summary>
    public string Protocol { get; set; } = "UDP/TLS/RTP/SAVPF";

    /// <summary>Media format tokens from the <c>m=</c> line, in preference order.</summary>
    public IList<string> Formats { get; } = new List<string>();

    /// <summary>Optional <c>i=</c> media title.</summary>
    public string? Information { get; set; }

    /// <summary>Optional <c>k=</c> encryption key line, preserved verbatim.</summary>
    public string? EncryptionKey { get; set; }

    /// <summary>True when the section is rejected, that is when the port is zero (JSEP).</summary>
    public bool IsRejected => Port == 0;

    /// <summary>True when the protocol is an RTP profile and the formats are payload types.</summary>
    public bool IsRtp => Protocol.Contains("RTP/", StringComparison.Ordinal);

    /// <summary>The <c>m=</c> line format tokens parsed as RTP payload types, skipping non-numeric ones.</summary>
    /// <returns>Payload types in <c>m=</c> line order.</returns>
    public IReadOnlyList<int> GetPayloadTypes()
    {
        var result = new List<int>(Formats.Count);
        foreach (var format in Formats)
        {
            if (int.TryParse(format, NumberStyles.None, CultureInfo.InvariantCulture, out var pt))
            {
                result.Add(pt);
            }
        }

        return result;
    }

    /// <summary><c>a=mid</c>. Setting <see langword="null"/> removes the attribute.</summary>
    public string? Mid
    {
        get => GetAttributeValue(SdpAttributeNames.Mid)?.Trim();
        set => SetOrRemove(SdpAttributeNames.Mid, value);
    }

    /// <summary>
    /// The direction attribute, or <see langword="null"/> when the section carries none. Per RFC 4566
    /// an absent direction means <see cref="MediaDirection.SendRecv"/>; see
    /// <see cref="DirectionOrDefault"/>.
    /// </summary>
    public MediaDirection? Direction
    {
        get
        {
            foreach (var attribute in Attributes)
            {
                if (SdpDirection.TryParse(attribute.Name, out var direction))
                {
                    return direction;
                }
            }

            return null;
        }

        set
        {
            var index = -1;
            for (var i = Attributes.Count - 1; i >= 0; i--)
            {
                if (!SdpDirection.TryParse(Attributes[i].Name, out _))
                {
                    continue;
                }

                if (index >= 0)
                {
                    Attributes.RemoveAt(index);
                }

                index = i;
            }

            if (value is null)
            {
                if (index >= 0)
                {
                    Attributes.RemoveAt(index);
                }

                return;
            }

            var replacement = new SdpAttribute(value.Value.ToAttributeName());
            if (index >= 0)
            {
                Attributes[index] = replacement;
            }
            else
            {
                Attributes.Add(replacement);
            }
        }
    }

    /// <summary>The direction attribute, defaulting to <see cref="MediaDirection.SendRecv"/> when absent.</summary>
    public MediaDirection DirectionOrDefault => Direction ?? SdpDirection.Default;

    /// <summary>Raw <c>a=rtcp</c> value, for example <c>9 IN IP4 0.0.0.0</c>.</summary>
    public string? Rtcp
    {
        get => GetAttributeValue(SdpAttributeNames.Rtcp);
        set => SetOrRemove(SdpAttributeNames.Rtcp, value);
    }

    /// <summary><c>a=rtcp-mux</c>.</summary>
    public bool RtcpMux
    {
        get => HasAttribute(SdpAttributeNames.RtcpMux);
        set => SetFlag(SdpAttributeNames.RtcpMux, value);
    }

    /// <summary><c>a=rtcp-rsize</c> (reduced-size RTCP, RFC 5506).</summary>
    public bool RtcpReducedSize
    {
        get => HasAttribute(SdpAttributeNames.RtcpReducedSize);
        set => SetFlag(SdpAttributeNames.RtcpReducedSize, value);
    }

    /// <summary>Every well-formed <c>a=rtpmap</c>, in document order.</summary>
    /// <returns>The mappings; malformed values are skipped.</returns>
    public IReadOnlyList<RtpMap> GetRtpMaps()
    {
        var result = new List<RtpMap>();
        foreach (var value in GetAttributeValues(SdpAttributeNames.RtpMap))
        {
            if (RtpMap.TryParse(value, out var map) && map is not null)
            {
                result.Add(map);
            }
        }

        return result;
    }

    /// <summary>The <c>a=rtpmap</c> for one payload type.</summary>
    /// <param name="payloadType">The payload type.</param>
    /// <returns>The mapping, or <see langword="null"/> when the section declares none.</returns>
    public RtpMap? GetRtpMap(int payloadType) =>
        GetRtpMaps().FirstOrDefault(m => m.PayloadType == payloadType);

    /// <summary>Adds or replaces the <c>a=rtpmap</c> for the payload type carried by <paramref name="rtpMap"/>.</summary>
    /// <param name="rtpMap">The mapping to write.</param>
    public void SetRtpMap(RtpMap rtpMap)
    {
        ArgumentNullException.ThrowIfNull(rtpMap);
        ReplaceIndexedAttribute(SdpAttributeNames.RtpMap, rtpMap.PayloadType, rtpMap.ToAttributeValue());
    }

    /// <summary>The raw <c>a=fmtp</c> parameter string for one payload type.</summary>
    /// <param name="payloadType">The payload type.</param>
    /// <returns>The text after the payload type, or <see langword="null"/> when absent.</returns>
    public string? GetFmtp(int payloadType)
    {
        var prefix = payloadType.ToString(CultureInfo.InvariantCulture);
        foreach (var value in GetAttributeValues(SdpAttributeNames.Fmtp))
        {
            var space = value.IndexOf(' ');
            if (space > 0 && string.Equals(value[..space], prefix, StringComparison.Ordinal))
            {
                return value[(space + 1)..];
            }
        }

        return null;
    }

    /// <summary>The <c>a=fmtp</c> parameters for one payload type, split on <c>;</c>.</summary>
    /// <param name="payloadType">The payload type.</param>
    /// <returns>An ordinal lookup; empty when the section declares no fmtp for the payload type.</returns>
    public IReadOnlyDictionary<string, string> GetFmtpParameters(int payloadType) =>
        FmtpParameters.Parse(GetFmtp(payloadType));

    /// <summary>Adds or replaces the <c>a=fmtp</c> for one payload type.</summary>
    /// <param name="payloadType">The payload type.</param>
    /// <param name="parameters">Raw parameter string, for example <c>minptime=10;useinbandfec=1</c>.</param>
    public void SetFmtp(int payloadType, string parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ReplaceIndexedAttribute(
            SdpAttributeNames.Fmtp,
            payloadType,
            string.Create(CultureInfo.InvariantCulture, $"{payloadType} {parameters}"));
    }

    /// <summary>Every well-formed <c>a=rtcp-fb</c> line, in document order.</summary>
    /// <returns>The entries, wildcard lines included; malformed values are skipped.</returns>
    public IReadOnlyList<RtcpFeedbackEntry> GetRtcpFeedbackEntries()
    {
        var result = new List<RtcpFeedbackEntry>();
        foreach (var value in GetAttributeValues(SdpAttributeNames.RtcpFeedback))
        {
            if (RtcpFeedbackEntry.TryParse(value, out var entry) && entry is not null)
            {
                result.Add(entry);
            }
        }

        return result;
    }

    /// <summary>
    /// The feedback capabilities that apply to one payload type: its own lines plus any
    /// <c>a=rtcp-fb:*</c> wildcard lines.
    /// </summary>
    /// <param name="payloadType">The payload type.</param>
    /// <returns>The capabilities in document order, without duplicates.</returns>
    public IReadOnlyList<RtcpFeedback> GetRtcpFeedback(int payloadType)
    {
        var result = new List<RtcpFeedback>();
        foreach (var entry in GetRtcpFeedbackEntries())
        {
            if (entry.AppliesTo(payloadType) && !result.Contains(entry.Feedback))
            {
                result.Add(entry.Feedback);
            }
        }

        return result;
    }

    /// <summary>Appends an <c>a=rtcp-fb</c> line for one payload type.</summary>
    /// <param name="payloadType">The payload type, or <see langword="null"/> for the <c>*</c> wildcard.</param>
    /// <param name="feedback">The capability to advertise.</param>
    public void AddRtcpFeedback(int? payloadType, RtcpFeedback feedback)
    {
        ArgumentNullException.ThrowIfNull(feedback);
        AddAttribute(
            SdpAttributeNames.RtcpFeedback,
            new RtcpFeedbackEntry(payloadType, feedback).ToAttributeValue());
    }

    /// <summary>Every well-formed <c>a=ssrc</c> line, in document order.</summary>
    /// <returns>The source attributes; malformed values are skipped.</returns>
    public IReadOnlyList<SsrcAttribute> GetSsrcAttributes()
    {
        var result = new List<SsrcAttribute>();
        foreach (var value in GetAttributeValues(SdpAttributeNames.Ssrc))
        {
            if (SsrcAttribute.TryParse(value, out var ssrc) && ssrc is not null)
            {
                result.Add(ssrc);
            }
        }

        return result;
    }

    /// <summary>The distinct synchronisation sources named by <c>a=ssrc</c> lines, in first-seen order.</summary>
    /// <returns>The source identifiers.</returns>
    public IReadOnlyList<uint> GetSsrcs()
    {
        var result = new List<uint>();
        foreach (var attribute in GetSsrcAttributes())
        {
            if (!result.Contains(attribute.Ssrc))
            {
                result.Add(attribute.Ssrc);
            }
        }

        return result;
    }

    /// <summary>The value of one source attribute, for example <c>cname</c>.</summary>
    /// <param name="ssrc">The synchronisation source.</param>
    /// <param name="name">Source attribute name, compared ordinally.</param>
    /// <returns>The value, or <see langword="null"/> when absent.</returns>
    public string? GetSsrcAttribute(uint ssrc, string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        foreach (var attribute in GetSsrcAttributes())
        {
            if (attribute.Ssrc == ssrc && string.Equals(attribute.Name, name, StringComparison.Ordinal))
            {
                return attribute.Value;
            }
        }

        return null;
    }

    /// <summary>The <c>cname</c> of one source.</summary>
    /// <param name="ssrc">The synchronisation source.</param>
    /// <returns>The canonical name, or <see langword="null"/> when absent.</returns>
    public string? GetSsrcCname(uint ssrc) => GetSsrcAttribute(ssrc, SdpAttributeNames.Cname);

    /// <summary>The per-source <c>msid</c> of one source.</summary>
    /// <param name="ssrc">The synchronisation source.</param>
    /// <returns>The stream and track identifiers, or <see langword="null"/> when absent.</returns>
    public SdpMsid? GetSsrcMsid(uint ssrc) =>
        SdpMsid.TryParse(GetSsrcAttribute(ssrc, SdpAttributeNames.Msid), out var msid) ? msid : null;

    /// <summary>Appends an <c>a=ssrc</c> line.</summary>
    /// <param name="ssrc">The synchronisation source.</param>
    /// <param name="name">Source attribute name, for example <c>cname</c>.</param>
    /// <param name="value">Source attribute value, or <see langword="null"/>.</param>
    public void AddSsrcAttribute(uint ssrc, string name, string? value)
    {
        ArgumentNullException.ThrowIfNull(name);
        AddAttribute(SdpAttributeNames.Ssrc, new SsrcAttribute(ssrc, name, value).ToAttributeValue());
    }

    /// <summary>Every well-formed <c>a=ssrc-group</c> line, in document order.</summary>
    /// <returns>The groups; malformed values are skipped.</returns>
    public IReadOnlyList<SsrcGroup> GetSsrcGroups()
    {
        var result = new List<SsrcGroup>();
        foreach (var value in GetAttributeValues(SdpAttributeNames.SsrcGroup))
        {
            if (SsrcGroup.TryParse(value, out var group) && group is not null)
            {
                result.Add(group);
            }
        }

        return result;
    }

    /// <summary>The section-level <c>a=msid</c>. Setting <see langword="null"/> removes the attribute.</summary>
    public SdpMsid? Msid
    {
        get => SdpMsid.TryParse(GetAttributeValue(SdpAttributeNames.Msid), out var msid) ? msid : null;
        set => SetOrRemove(SdpAttributeNames.Msid, value?.ToAttributeValue());
    }

    /// <summary>Every well-formed <c>a=extmap</c>, in document order.</summary>
    /// <returns>The header extension mappings; malformed values are skipped.</returns>
    public IReadOnlyList<SdpExtMap> GetExtMaps()
    {
        var result = new List<SdpExtMap>();
        foreach (var value in GetAttributeValues(SdpAttributeNames.ExtMap))
        {
            if (SdpExtMap.TryParse(value, out var extMap) && extMap is not null)
            {
                result.Add(extMap);
            }
        }

        return result;
    }

    /// <summary>Appends an <c>a=extmap</c> line.</summary>
    /// <param name="extMap">The header extension mapping.</param>
    public void AddExtMap(SdpExtMap extMap)
    {
        ArgumentNullException.ThrowIfNull(extMap);
        AddAttribute(SdpAttributeNames.ExtMap, extMap.ToAttributeValue());
    }

    /// <summary>
    /// Raw <c>a=candidate</c> values, in document order. Candidates stay strings here: parsing them
    /// belongs to the ICE layer.
    /// </summary>
    /// <returns>The candidate values, without the <c>a=candidate:</c> prefix.</returns>
    public IReadOnlyList<string> GetCandidates() =>
        GetAttributeValues(SdpAttributeNames.Candidate).ToArray();

    /// <summary>Appends an <c>a=candidate</c> line.</summary>
    /// <param name="candidate">The candidate value, without the <c>a=candidate:</c> prefix.</param>
    public void AddCandidate(string candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        AddAttribute(SdpAttributeNames.Candidate, candidate);
    }

    /// <summary><c>a=end-of-candidates</c>.</summary>
    public bool EndOfCandidates
    {
        get => HasAttribute(SdpAttributeNames.EndOfCandidates);
        set => SetFlag(SdpAttributeNames.EndOfCandidates, value);
    }

    /// <summary><c>a=sctp-port</c>. Setting <see langword="null"/> removes the attribute.</summary>
    public int? SctpPort
    {
        get => GetIntAttribute(SdpAttributeNames.SctpPort);
        set => SetIntAttribute(SdpAttributeNames.SctpPort, value);
    }

    /// <summary><c>a=max-message-size</c>. Setting <see langword="null"/> removes the attribute.</summary>
    public int? MaxMessageSize
    {
        get => GetIntAttribute(SdpAttributeNames.MaxMessageSize);
        set => SetIntAttribute(SdpAttributeNames.MaxMessageSize, value);
    }

    /// <summary>Renders the <c>m=</c> line without the leading <c>m=</c>.</summary>
    /// <returns>For example <c>audio 9 UDP/TLS/RTP/SAVPF 111</c>.</returns>
    public string ToMediaLineValue()
    {
        var port = PortCount is { } count
            ? string.Create(CultureInfo.InvariantCulture, $"{Port}/{count}")
            : Port.ToString(CultureInfo.InvariantCulture);
        var head = Media + " " + port + " " + Protocol;
        return Formats.Count == 0 ? head : head + " " + string.Join(' ', Formats);
    }

    /// <summary>
    /// Serializes this m-section on its own: the <c>m=</c> line and every line that belongs to it,
    /// CRLF terminated.
    /// </summary>
    /// <returns>The m-section text.</returns>
    public string ToSdpString() => SdpWriter.WriteMedia(this);

    /// <summary>Renders the <c>m=</c> line without a line terminator.</summary>
    /// <returns>For example <c>m=audio 9 UDP/TLS/RTP/SAVPF 111</c>.</returns>
    public override string ToString() => "m=" + ToMediaLineValue();

    private int? GetIntAttribute(string name) =>
        int.TryParse(GetAttributeValue(name)?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;

    private void SetIntAttribute(string name, int? value) =>
        SetOrRemove(name, value?.ToString(CultureInfo.InvariantCulture));

    private void ReplaceIndexedAttribute(string name, int payloadType, string attributeValue)
    {
        var prefix = payloadType.ToString(CultureInfo.InvariantCulture) + " ";
        for (var i = 0; i < Attributes.Count; i++)
        {
            var attribute = Attributes[i];
            if (string.Equals(attribute.Name, name, StringComparison.Ordinal) &&
                attribute.Value is { } value &&
                value.StartsWith(prefix, StringComparison.Ordinal))
            {
                Attributes[i] = new SdpAttribute(name, attributeValue);
                return;
            }
        }

        Attributes.Add(new SdpAttribute(name, attributeValue));
    }
}
