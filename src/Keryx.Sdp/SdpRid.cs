namespace Keryx.Sdp;

/// <summary>The direction token of an <c>a=rid</c> line (RFC 8851 §10): the RID is sent, or received.</summary>
public enum RidDirection
{
    /// <summary>The RID identifies a stream this endpoint sends: <c>a=rid:&lt;id&gt; send</c>.</summary>
    Send,

    /// <summary>The RID identifies a stream this endpoint receives: <c>a=rid:&lt;id&gt; recv</c>.</summary>
    Recv,
}

/// <summary>
/// One key=value restriction from the parameter list of an <c>a=rid</c> line, for example
/// <c>max-width=1280</c> or <c>pt=96,97</c> (RFC 8851 §10). Values are preserved verbatim; Keryx does
/// not interpret them.
/// </summary>
/// <param name="Key">The restriction name, for example <c>max-width</c>, <c>max-fps</c> or <c>pt</c>.</param>
/// <param name="Value">The restriction value, preserved as written.</param>
public sealed record SdpRidRestriction(string Key, string Value)
{
    /// <summary>Renders the restriction as it appears in the parameter list.</summary>
    /// <returns>For example <c>max-width=1280</c>.</returns>
    public override string ToString() => Key + "=" + Value;
}

/// <summary>
/// An <c>a=rid</c> line (RFC 8851 §10): <c>a=rid:&lt;id&gt; &lt;direction&gt; [&lt;restriction&gt;;...]</c>.
/// A RID names one encoding of a media source; a simulcast video source advertises several, one per
/// spatial/quality layer, and each incoming RTP packet carries its RID in the RFC 8852 header extension.
/// </summary>
/// <param name="Id">The RID identifier: alphanumeric plus <c>-</c> and <c>_</c>, at most 255 characters.</param>
/// <param name="Direction">Whether the RID is sent or received.</param>
/// <param name="Restrictions">The restriction list, in document order; empty when the line carries none.</param>
public sealed record SdpRid(string Id, RidDirection Direction, IReadOnlyList<SdpRidRestriction> Restrictions)
{
    /// <summary>Creates a RID with no restrictions.</summary>
    /// <param name="id">The RID identifier.</param>
    /// <param name="direction">Whether the RID is sent or received.</param>
    public SdpRid(string id, RidDirection direction)
        : this(id, direction, Array.Empty<SdpRidRestriction>())
    {
    }

    /// <summary>True when the identifier is a well-formed RID: 1–255 characters of <c>[A-Za-z0-9-_]</c>.</summary>
    /// <param name="id">The candidate identifier.</param>
    /// <returns>True when <paramref name="id"/> is a legal <c>rid-id</c> (RFC 8851 §10).</returns>
    public static bool IsValidId(string? id)
    {
        if (id is null || id.Length is 0 or > 255)
        {
            return false;
        }

        foreach (var c in id)
        {
            var ok = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
            if (!ok)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Parses an <c>a=rid</c> attribute value. Never throws.</summary>
    /// <param name="value">The attribute value, without the <c>a=rid:</c> prefix.</param>
    /// <param name="rid">Receives the parsed line.</param>
    /// <returns>True when the identifier and a valid direction are present.</returns>
    public static bool TryParse(string? value, out SdpRid? rid)
    {
        rid = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var fields = value.Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 2 || !IsValidId(fields[0]))
        {
            return false;
        }

        RidDirection direction;
        if (string.Equals(fields[1], "send", StringComparison.Ordinal))
        {
            direction = RidDirection.Send;
        }
        else if (string.Equals(fields[1], "recv", StringComparison.Ordinal))
        {
            direction = RidDirection.Recv;
        }
        else
        {
            return false;
        }

        var restrictions = fields.Length > 2 ? ParseRestrictions(fields[2]) : Array.Empty<SdpRidRestriction>();
        rid = new SdpRid(fields[0], direction, restrictions);
        return true;
    }

    private static IReadOnlyList<SdpRidRestriction> ParseRestrictions(string text)
    {
        var result = new List<SdpRidRestriction>();
        foreach (var part in text.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0)
            {
                // A malformed fragment (no key, or bare token) is preserved as a valueless restriction
                // rather than dropped, so a round trip does not silently rewrite the peer's line.
                result.Add(new SdpRidRestriction(part, string.Empty));
                continue;
            }

            result.Add(new SdpRidRestriction(part[..eq], part[(eq + 1)..]));
        }

        return result;
    }

    /// <summary>Renders the value part of the <c>a=rid</c> attribute.</summary>
    /// <returns>For example <c>hi send max-width=1280;max-height=720</c>.</returns>
    public string ToAttributeValue()
    {
        var head = Id + " " + (Direction == RidDirection.Send ? "send" : "recv");
        if (Restrictions.Count == 0)
        {
            return head;
        }

        var restrictions = new string[Restrictions.Count];
        for (var i = 0; i < Restrictions.Count; i++)
        {
            var r = Restrictions[i];
            restrictions[i] = r.Value.Length == 0 ? r.Key : r.Key + "=" + r.Value;
        }

        return head + " " + string.Join(';', restrictions);
    }

    /// <summary>Renders the complete attribute without a line terminator.</summary>
    /// <returns>For example <c>a=rid:hi send max-width=1280</c>.</returns>
    public override string ToString() => "a=rid:" + ToAttributeValue();
}
