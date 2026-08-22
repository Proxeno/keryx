namespace Keryx.Sdp;

/// <summary>
/// One <c>a=</c> attribute: either a flag such as <c>a=rtcp-mux</c> or a name/value pair such as
/// <c>a=mid:0</c>.
/// </summary>
/// <param name="Name">Attribute name: the text between <c>a=</c> and the first colon.</param>
/// <param name="Value">
/// Raw attribute value: the text after the first colon, preserved verbatim including any leading
/// space (Chrome writes <c>a=msid-semantic: WMS</c>). <see langword="null"/> for flag attributes.
/// </param>
public sealed record SdpAttribute(string Name, string? Value = null)
{
    /// <summary>True when the attribute carries no value part.</summary>
    public bool IsFlag => Value is null;

    /// <summary>Parses the text that follows <c>a=</c> on an attribute line.</summary>
    /// <param name="text">Attribute body, without the <c>a=</c> prefix and without line terminator.</param>
    /// <returns>The parsed attribute.</returns>
    public static SdpAttribute Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var colon = text.IndexOf(':');
        return colon < 0
            ? new SdpAttribute(text, null)
            : new SdpAttribute(text[..colon], text[(colon + 1)..]);
    }

    /// <summary>Renders the attribute without the leading <c>a=</c>.</summary>
    /// <returns>For example <c>mid:0</c> or <c>rtcp-mux</c>.</returns>
    public string ToAttributeValue() => Value is null ? Name : Name + ":" + Value;

    /// <summary>Renders the complete <c>a=</c> line without a line terminator.</summary>
    /// <returns>For example <c>a=mid:0</c>.</returns>
    public override string ToString() => "a=" + ToAttributeValue();
}
