using System.Globalization;

namespace Keryx.Sdp;

/// <summary>
/// One <c>a=ssrc</c> line: <c>a=ssrc:&lt;ssrc&gt; &lt;attribute&gt;[:&lt;value&gt;]</c>.
/// </summary>
/// <param name="Ssrc">The synchronisation source identifier.</param>
/// <param name="Name">Source attribute name, for example <c>cname</c> or <c>msid</c>.</param>
/// <param name="Value">Source attribute value, or <see langword="null"/> for a valueless attribute.</param>
public sealed record SsrcAttribute(uint Ssrc, string Name, string? Value = null)
{
    /// <summary>Parses an <c>a=ssrc</c> attribute value.</summary>
    /// <param name="value">The attribute value, without the <c>a=ssrc:</c> prefix.</param>
    /// <param name="attribute">Receives the parsed source attribute.</param>
    /// <returns>True when the value is a well-formed ssrc line.</returns>
    public static bool TryParse(string? value, out SsrcAttribute? attribute)
    {
        attribute = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        var space = trimmed.IndexOf(' ');
        var ssrcText = space < 0 ? trimmed : trimmed[..space];
        if (!uint.TryParse(ssrcText, NumberStyles.None, CultureInfo.InvariantCulture, out var ssrc))
        {
            return false;
        }

        if (space < 0)
        {
            return false;
        }

        var rest = trimmed[(space + 1)..];
        var colon = rest.IndexOf(':');
        attribute = colon < 0
            ? new SsrcAttribute(ssrc, rest, null)
            : new SsrcAttribute(ssrc, rest[..colon], rest[(colon + 1)..]);
        return true;
    }

    /// <summary>Renders the value part of the <c>a=ssrc</c> attribute.</summary>
    /// <returns>For example <c>1234 cname:abc</c>.</returns>
    public string ToAttributeValue()
    {
        var head = Ssrc.ToString(CultureInfo.InvariantCulture) + " " + Name;
        return Value is null ? head : head + ":" + Value;
    }

    /// <summary>Renders the complete attribute without a line terminator.</summary>
    /// <returns>For example <c>a=ssrc:1234 cname:abc</c>.</returns>
    public override string ToString() => "a=ssrc:" + ToAttributeValue();
}

/// <summary>
/// An <c>a=ssrc-group</c> line: <c>a=ssrc-group:&lt;semantics&gt; &lt;ssrc&gt;...</c>, used for RTX
/// (<c>FID</c>) and simulcast (<c>SIM</c>) associations.
/// </summary>
/// <param name="Semantics">Grouping semantics, for example <c>FID</c>.</param>
/// <param name="Ssrcs">Member sources, in document order.</param>
public sealed record SsrcGroup(string Semantics, IReadOnlyList<uint> Ssrcs)
{
    /// <summary>Parses an <c>a=ssrc-group</c> attribute value.</summary>
    /// <param name="value">The attribute value, without the <c>a=ssrc-group:</c> prefix.</param>
    /// <param name="group">Receives the parsed group.</param>
    /// <returns>True when semantics and at least one numeric source are present.</returns>
    public static bool TryParse(string? value, out SsrcGroup? group)
    {
        group = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var fields = value.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 2)
        {
            return false;
        }

        var ssrcs = new List<uint>(fields.Length - 1);
        for (var i = 1; i < fields.Length; i++)
        {
            if (uint.TryParse(fields[i], NumberStyles.None, CultureInfo.InvariantCulture, out var ssrc))
            {
                ssrcs.Add(ssrc);
            }
        }

        if (ssrcs.Count == 0)
        {
            return false;
        }

        group = new SsrcGroup(fields[0], ssrcs);
        return true;
    }

    /// <summary>Renders the value part of the <c>a=ssrc-group</c> attribute.</summary>
    /// <returns>For example <c>FID 1 2</c>.</returns>
    public string ToAttributeValue() =>
        Semantics + " " + string.Join(' ', Ssrcs.Select(static s => s.ToString(CultureInfo.InvariantCulture)));

    /// <summary>Renders the complete attribute without a line terminator.</summary>
    /// <returns>For example <c>a=ssrc-group:FID 1 2</c>.</returns>
    public override string ToString() => "a=ssrc-group:" + ToAttributeValue();
}
