using Keryx.Core;

namespace Keryx.Sdp;

/// <summary>
/// A complete SDP document: the session-level lines plus the ordered list of m-sections.
/// </summary>
/// <remarks>
/// The model is deliberately lossless. Attributes Keryx does not interpret are preserved verbatim in
/// <see cref="SdpSection.Attributes"/> in their original order, so
/// <c>SessionDescription.Parse(text).ToSdpString()</c> reproduces a browser's SDP byte for byte once
/// line endings are normalised to CRLF.
/// </remarks>
public sealed class SessionDescription : SdpSection
{
    /// <summary>The line terminator SDP requires and this serializer always emits.</summary>
    public const string LineTerminator = "\r\n";

    /// <summary><c>v=</c>. Always 0 in practice.</summary>
    public int Version { get; set; }

    /// <summary><c>o=</c> origin line.</summary>
    public SdpOrigin Origin { get; set; } = SdpOrigin.Default;

    /// <summary><c>s=</c> session name. WebRTC uses <c>-</c>.</summary>
    public string SessionName { get; set; } = "-";

    /// <summary>Optional <c>i=</c> session information.</summary>
    public string? Information { get; set; }

    /// <summary>Optional <c>u=</c> description URI.</summary>
    public string? Uri { get; set; }

    /// <summary>Raw <c>e=</c> email lines, in document order.</summary>
    public IList<string> Emails { get; } = new List<string>();

    /// <summary>Raw <c>p=</c> phone lines, in document order.</summary>
    public IList<string> PhoneNumbers { get; } = new List<string>();

    /// <summary><c>t=</c> lines with their <c>r=</c> repeats. WebRTC emits exactly <c>t=0 0</c>.</summary>
    public IList<SdpTiming> Timings { get; } = new List<SdpTiming>();

    /// <summary>Optional <c>z=</c> time zone adjustment line, preserved verbatim.</summary>
    public string? TimeZoneAdjustments { get; set; }

    /// <summary>Optional <c>k=</c> encryption key line, preserved verbatim.</summary>
    public string? EncryptionKey { get; set; }

    /// <summary>The m-sections, in document order. JSEP requires this order to be stable across renegotiations.</summary>
    public IList<MediaDescription> MediaDescriptions { get; } = new List<MediaDescription>();

    /// <summary>Every well-formed <c>a=group</c> line, in document order.</summary>
    /// <returns>The groups; malformed values are skipped.</returns>
    public IReadOnlyList<SdpGroup> GetGroups()
    {
        var result = new List<SdpGroup>();
        foreach (var value in GetAttributeValues(SdpAttributeNames.Group))
        {
            if (SdpGroup.TryParse(value, out var group) && group is not null)
            {
                result.Add(group);
            }
        }

        return result;
    }

    /// <summary>The mids listed by <c>a=group:BUNDLE</c>.</summary>
    /// <returns>The bundled mids in document order, empty when the session declares no BUNDLE group.</returns>
    public IReadOnlyList<string> GetBundleGroup()
    {
        foreach (var group in GetGroups())
        {
            if (string.Equals(group.Semantics, SdpGroup.BundleSemantics, StringComparison.Ordinal))
            {
                return group.Identifiers;
            }
        }

        return [];
    }

    /// <summary>Writes <c>a=group:BUNDLE</c>. Passing an empty list removes the group.</summary>
    /// <param name="mids">The mids to bundle, in m-section order. The first becomes the BUNDLE tag.</param>
    public void SetBundleGroup(IEnumerable<string> mids)
    {
        ArgumentNullException.ThrowIfNull(mids);
        var list = mids.ToList();
        for (var i = Attributes.Count - 1; i >= 0; i--)
        {
            var attribute = Attributes[i];
            if (string.Equals(attribute.Name, SdpAttributeNames.Group, StringComparison.Ordinal) &&
                SdpGroup.TryParse(attribute.Value, out var group) &&
                group is not null &&
                string.Equals(group.Semantics, SdpGroup.BundleSemantics, StringComparison.Ordinal))
            {
                Attributes.RemoveAt(i);
            }
        }

        if (list.Count == 0)
        {
            return;
        }

        Attributes.Add(new SdpAttribute(
            SdpAttributeNames.Group,
            new SdpGroup(SdpGroup.BundleSemantics, list).ToAttributeValue()));
    }

    /// <summary>
    /// The raw <c>a=msid-semantic</c> value. Chrome writes <c>a=msid-semantic: WMS &lt;id&gt;</c>, so the
    /// raw value has a leading space; use <see cref="GetWmsStreamIds"/> for the parsed form.
    /// </summary>
    public string? MsidSemantic
    {
        get => GetAttributeValue(SdpAttributeNames.MsidSemantic);
        set => SetOrRemove(SdpAttributeNames.MsidSemantic, value);
    }

    /// <summary>The stream identifiers listed after the <c>WMS</c> token in <c>a=msid-semantic</c>.</summary>
    /// <returns>The identifiers, empty when the attribute is absent or lists none.</returns>
    public IReadOnlyList<string> GetWmsStreamIds()
    {
        var value = MsidSemantic;
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        var fields = value.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return fields.Length <= 1 || !string.Equals(fields[0], "WMS", StringComparison.Ordinal)
            ? []
            : fields[1..];
    }

    /// <summary>Writes <c>a=msid-semantic: WMS &lt;ids&gt;</c> using Chrome's leading-space convention.</summary>
    /// <param name="streamIds">MediaStream identifiers; may be empty for a bare <c>WMS</c> token.</param>
    public void SetWmsStreamIds(params string[] streamIds)
    {
        ArgumentNullException.ThrowIfNull(streamIds);
        MsidSemantic = streamIds.Length == 0 ? " WMS" : " WMS " + string.Join(' ', streamIds);
    }

    /// <summary><c>a=extmap-allow-mixed</c>.</summary>
    public bool ExtMapAllowMixed
    {
        get => HasAttribute(SdpAttributeNames.ExtMapAllowMixed);
        set => SetFlag(SdpAttributeNames.ExtMapAllowMixed, value);
    }

    /// <summary>The mids of the m-sections, in order. Sections without <c>a=mid</c> yield <see langword="null"/>.</summary>
    /// <returns>One entry per m-section.</returns>
    public IReadOnlyList<string?> GetMids() => MediaDescriptions.Select(static m => m.Mid).ToArray();

    /// <summary>Finds the m-section carrying <paramref name="mid"/>.</summary>
    /// <param name="mid">The mid to look up, compared ordinally.</param>
    /// <returns>The m-section, or <see langword="null"/> when no section declares that mid.</returns>
    public MediaDescription? GetMediaByMid(string mid)
    {
        ArgumentNullException.ThrowIfNull(mid);
        return MediaDescriptions.FirstOrDefault(m => string.Equals(m.Mid, mid, StringComparison.Ordinal));
    }

    /// <summary>Parses an SDP document. Never throws on well-formed-but-unusual input.</summary>
    /// <param name="text">The SDP text. Both CRLF and bare LF line endings are accepted.</param>
    /// <param name="logger">Optional logger notified about lines the parser skipped.</param>
    /// <returns>The parsed description.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="text"/> is <see langword="null"/>.</exception>
    public static SessionDescription Parse(string text, IKeryxLogger? logger = null) =>
        SdpParser.Parse(text, logger);

    /// <summary>Serializes the description, always using CRLF line endings and a trailing CRLF.</summary>
    /// <returns>The SDP text.</returns>
    public string ToSdpString() => SdpWriter.Write(this);

    /// <summary>Serializes the description; identical to <see cref="ToSdpString"/>.</summary>
    /// <returns>The SDP text.</returns>
    public override string ToString() => ToSdpString();
}
