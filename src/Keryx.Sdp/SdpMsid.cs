namespace Keryx.Sdp;

/// <summary>
/// An <c>a=msid</c> value (RFC 8830): <c>&lt;stream-id&gt; [&lt;track-id&gt;]</c>. The same shape is
/// carried by the per-source <c>a=ssrc:&lt;ssrc&gt; msid:...</c> attribute.
/// </summary>
/// <param name="StreamId">MediaStream identifier, or <c>-</c> for "no stream".</param>
/// <param name="TrackId">MediaStreamTrack identifier, absent on some legacy lines.</param>
public sealed record SdpMsid(string StreamId, string? TrackId = null)
{
    /// <summary>Parses an <c>a=msid</c> value.</summary>
    /// <param name="value">The attribute value, without the <c>a=msid:</c> prefix.</param>
    /// <param name="msid">Receives the parsed value.</param>
    /// <returns>True when at least a stream identifier is present.</returns>
    public static bool TryParse(string? value, out SdpMsid? msid)
    {
        msid = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var fields = value.Trim().Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        msid = new SdpMsid(fields[0], fields.Length > 1 ? fields[1].Trim() : null);
        return true;
    }

    /// <summary>Renders the value part of the <c>a=msid</c> attribute.</summary>
    /// <returns>For example <c>stream track</c>.</returns>
    public string ToAttributeValue() => TrackId is null ? StreamId : StreamId + " " + TrackId;

    /// <summary>Renders the complete attribute without a line terminator.</summary>
    /// <returns>For example <c>a=msid:stream track</c>.</returns>
    public override string ToString() => "a=msid:" + ToAttributeValue();
}
