namespace Keryx.Sdp;

/// <summary>
/// An <c>a=group</c> line (RFC 5888): <c>a=group:&lt;semantics&gt; &lt;mid&gt;...</c>. WebRTC uses
/// <c>BUNDLE</c> to multiplex every m-section onto a single transport.
/// </summary>
/// <param name="Semantics">Grouping semantics token, for example <c>BUNDLE</c>.</param>
/// <param name="Identifiers">Member mids, in document order. The first is the BUNDLE tag.</param>
public sealed record SdpGroup(string Semantics, IReadOnlyList<string> Identifiers)
{
    /// <summary>The <c>BUNDLE</c> semantics token.</summary>
    public const string BundleSemantics = "BUNDLE";

    /// <summary>Parses an <c>a=group</c> attribute value.</summary>
    /// <param name="value">The attribute value, without the <c>a=group:</c> prefix.</param>
    /// <param name="group">Receives the parsed group.</param>
    /// <returns>True when a semantics token is present; the identifier list may be empty.</returns>
    public static bool TryParse(string? value, out SdpGroup? group)
    {
        group = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var fields = value.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        group = new SdpGroup(fields[0], fields[1..]);
        return true;
    }

    /// <summary>Renders the value part of the <c>a=group</c> attribute.</summary>
    /// <returns>For example <c>BUNDLE 0 1 2</c>.</returns>
    public string ToAttributeValue() =>
        Identifiers.Count == 0 ? Semantics : Semantics + " " + string.Join(' ', Identifiers);

    /// <summary>Renders the complete attribute without a line terminator.</summary>
    /// <returns>For example <c>a=group:BUNDLE 0 1 2</c>.</returns>
    public override string ToString() => "a=group:" + ToAttributeValue();
}
