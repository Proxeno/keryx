using System.Globalization;

namespace Keryx.Sdp;

/// <summary>
/// An <c>a=rtpmap</c> entry: <c>a=rtpmap:&lt;pt&gt; &lt;encoding&gt;/&lt;clock&gt;[/&lt;channels&gt;]</c>.
/// </summary>
/// <param name="PayloadType">RTP payload type the mapping applies to.</param>
/// <param name="EncodingName">Encoding name, for example <c>opus</c> or <c>H264</c>.</param>
/// <param name="ClockRate">RTP clock rate in Hz.</param>
/// <param name="Channels">Channel count, present for audio only (<c>opus/48000/2</c>).</param>
public sealed record RtpMap(int PayloadType, string EncodingName, int ClockRate, int? Channels = null)
{
    /// <summary>Parses an <c>a=rtpmap</c> attribute value.</summary>
    /// <param name="value">The attribute value, without the <c>a=rtpmap:</c> prefix.</param>
    /// <param name="rtpMap">Receives the parsed mapping.</param>
    /// <returns>True when the value is a well-formed rtpmap.</returns>
    public static bool TryParse(string? value, out RtpMap? rtpMap)
    {
        rtpMap = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var space = value.IndexOf(' ');
        if (space <= 0)
        {
            return false;
        }

        if (!int.TryParse(value.AsSpan(0, space), NumberStyles.None, CultureInfo.InvariantCulture, out var pt))
        {
            return false;
        }

        var encoding = value[(space + 1)..].Trim();
        if (encoding.Length == 0)
        {
            return false;
        }

        var fields = encoding.Split('/');
        if (fields.Length < 2 ||
            !int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var clock))
        {
            return false;
        }

        int? channels = null;
        if (fields.Length > 2 &&
            int.TryParse(fields[2], NumberStyles.None, CultureInfo.InvariantCulture, out var parsedChannels))
        {
            channels = parsedChannels;
        }

        rtpMap = new RtpMap(pt, fields[0], clock, channels);
        return true;
    }

    /// <summary>Renders the encoding portion, <c>&lt;encoding&gt;/&lt;clock&gt;[/&lt;channels&gt;]</c>.</summary>
    /// <returns>For example <c>opus/48000/2</c>.</returns>
    public string ToEncodingString() => Channels is { } channels
        ? string.Create(CultureInfo.InvariantCulture, $"{EncodingName}/{ClockRate}/{channels}")
        : string.Create(CultureInfo.InvariantCulture, $"{EncodingName}/{ClockRate}");

    /// <summary>Renders the value part of the <c>a=rtpmap</c> attribute.</summary>
    /// <returns>For example <c>111 opus/48000/2</c>.</returns>
    public string ToAttributeValue() =>
        string.Create(CultureInfo.InvariantCulture, $"{PayloadType} {ToEncodingString()}");

    /// <summary>Renders the complete attribute without a line terminator.</summary>
    /// <returns>For example <c>a=rtpmap:111 opus/48000/2</c>.</returns>
    public override string ToString() => "a=rtpmap:" + ToAttributeValue();
}
