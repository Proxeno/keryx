using System.Globalization;

namespace Keryx.Sdp;

/// <summary>
/// An <c>a=extmap</c> line (RFC 8285):
/// <c>a=extmap:&lt;id&gt;[/&lt;direction&gt;] &lt;uri&gt; [&lt;parameters&gt;]</c>.
/// </summary>
/// <param name="Id">Header extension identifier carried in the RTP header extension.</param>
/// <param name="Uri">Extension URI, for example <c>urn:ietf:params:rtp-hdrext:sdes:mid</c>.</param>
/// <param name="Direction">Optional direction qualifier appended to the id as <c>/sendonly</c>.</param>
/// <param name="Parameters">Optional trailing extension attributes, preserved verbatim.</param>
public sealed record SdpExtMap(int Id, string Uri, MediaDirection? Direction = null, string? Parameters = null)
{
    /// <summary>
    /// URI of the transport-wide congestion-control header extension
    /// (<c>draft-holmer-rmcat-transport-wide-cc-extensions-01</c>), which carries a monotonically
    /// increasing transport-wide sequence number so the remote can return TWCC feedback.
    /// </summary>
    public const string TransportWideCcUri =
        "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

    /// <summary>
    /// URI of the absolute send time header extension
    /// (<c>http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time</c>), which carries the sender's
    /// 6.18 fixed-point transmit timestamp so the receiver can run a delay-gradient estimator and return
    /// REMB.
    /// </summary>
    public const string AbsoluteSendTimeUri = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

    /// <summary>Creates the <c>a=extmap</c> for the transport-wide congestion-control extension.</summary>
    /// <param name="id">The header-extension identifier to negotiate; 1–14 for the one-byte form.</param>
    /// <returns>An extmap mapping <paramref name="id"/> to <see cref="TransportWideCcUri"/>.</returns>
    public static SdpExtMap TransportWideCc(int id) => new(id, TransportWideCcUri);

    /// <summary>Creates the <c>a=extmap</c> for the absolute send time extension.</summary>
    /// <param name="id">The header-extension identifier to negotiate; 1–14 for the one-byte form.</param>
    /// <returns>An extmap mapping <paramref name="id"/> to <see cref="AbsoluteSendTimeUri"/>.</returns>
    public static SdpExtMap AbsoluteSendTime(int id) => new(id, AbsoluteSendTimeUri);

    /// <summary>True when this mapping is the transport-wide congestion-control extension.</summary>
    public bool IsTransportWideCc => string.Equals(Uri, TransportWideCcUri, StringComparison.Ordinal);

    /// <summary>True when this mapping is the absolute send time extension.</summary>
    public bool IsAbsoluteSendTime => string.Equals(Uri, AbsoluteSendTimeUri, StringComparison.Ordinal);

    /// <summary>Parses an <c>a=extmap</c> attribute value.</summary>
    /// <param name="value">The attribute value, without the <c>a=extmap:</c> prefix.</param>
    /// <param name="extMap">Receives the parsed mapping.</param>
    /// <returns>True when an identifier and a URI are present.</returns>
    public static bool TryParse(string? value, out SdpExtMap? extMap)
    {
        extMap = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var fields = value.Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 2)
        {
            return false;
        }

        var idField = fields[0];
        MediaDirection? direction = null;
        var slash = idField.IndexOf('/');
        if (slash >= 0)
        {
            if (SdpDirection.TryParse(idField[(slash + 1)..], out var parsedDirection))
            {
                direction = parsedDirection;
            }

            idField = idField[..slash];
        }

        if (!int.TryParse(idField, NumberStyles.None, CultureInfo.InvariantCulture, out var id))
        {
            return false;
        }

        extMap = new SdpExtMap(id, fields[1], direction, fields.Length > 2 ? fields[2] : null);
        return true;
    }

    /// <summary>Renders the value part of the <c>a=extmap</c> attribute.</summary>
    /// <returns>For example <c>3 urn:ietf:params:rtp-hdrext:sdes:mid</c>.</returns>
    public string ToAttributeValue()
    {
        var head = Id.ToString(CultureInfo.InvariantCulture);
        if (Direction is { } direction)
        {
            head += "/" + direction.ToAttributeName();
        }

        var text = head + " " + Uri;
        return Parameters is null ? text : text + " " + Parameters;
    }

    /// <summary>Renders the complete attribute without a line terminator.</summary>
    /// <returns>For example <c>a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid</c>.</returns>
    public override string ToString() => "a=extmap:" + ToAttributeValue();
}
