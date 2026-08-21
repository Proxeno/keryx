using System.Globalization;

namespace Keryx.Sdp;

/// <summary>
/// One RTCP feedback capability: the type token and its optional parameter, as they appear after the
/// payload type in <c>a=rtcp-fb:&lt;pt&gt; &lt;type&gt; [&lt;parameter&gt;]</c>.
/// </summary>
/// <param name="Type">Feedback type token, for example <c>nack</c>, <c>ccm</c>, <c>transport-cc</c>.</param>
/// <param name="Parameter">
/// Optional parameter, for example <c>pli</c> for <c>nack</c> or <c>fir</c> for <c>ccm</c>.
/// <see langword="null"/> renders the bare form.
/// </param>
/// <remarks>
/// Bare <c>nack</c> and <c>nack pli</c> are distinct capabilities. A sender that advertises bare
/// <c>nack</c> is claiming generic NACK retransmission support; advertise it only when the RTP layer
/// actually implements RTX, otherwise remote peers will request retransmissions that never arrive.
/// </remarks>
public sealed record RtcpFeedback(string Type, string? Parameter = null)
{
    /// <summary>Generic NACK (RFC 4585): <c>a=rtcp-fb:&lt;pt&gt; nack</c>.</summary>
    public static RtcpFeedback Nack { get; } = new("nack");

    /// <summary>Picture Loss Indication: <c>a=rtcp-fb:&lt;pt&gt; nack pli</c>.</summary>
    public static RtcpFeedback NackPli { get; } = new("nack", "pli");

    /// <summary>Full Intra Request: <c>a=rtcp-fb:&lt;pt&gt; ccm fir</c>.</summary>
    public static RtcpFeedback CcmFir { get; } = new("ccm", "fir");

    /// <summary>Transport-wide congestion control: <c>a=rtcp-fb:&lt;pt&gt; transport-cc</c>.</summary>
    public static RtcpFeedback TransportCc { get; } = new("transport-cc");

    /// <summary>Receiver estimated maximum bitrate: <c>a=rtcp-fb:&lt;pt&gt; goog-remb</c>.</summary>
    public static RtcpFeedback GoogRemb { get; } = new("goog-remb");

    /// <summary>Renders the feedback without any payload type prefix.</summary>
    /// <returns>For example <c>nack pli</c> or <c>transport-cc</c>.</returns>
    public override string ToString() => Parameter is null ? Type : Type + " " + Parameter;
}

/// <summary>
/// A complete <c>a=rtcp-fb</c> line: a <see cref="RtcpFeedback"/> bound to one payload type, or to
/// every payload type when the line uses the <c>*</c> wildcard.
/// </summary>
/// <param name="PayloadType">Payload type, or <see langword="null"/> for the <c>*</c> wildcard.</param>
/// <param name="Feedback">The feedback capability.</param>
public sealed record RtcpFeedbackEntry(int? PayloadType, RtcpFeedback Feedback)
{
    /// <summary>True when the line applies to all payload types (<c>a=rtcp-fb:*</c>).</summary>
    public bool IsWildcard => PayloadType is null;

    /// <summary>True when this entry governs <paramref name="payloadType"/>, directly or by wildcard.</summary>
    /// <param name="payloadType">The payload type to test.</param>
    /// <returns>True when the entry applies.</returns>
    public bool AppliesTo(int payloadType) => PayloadType is null || PayloadType == payloadType;

    /// <summary>Parses an <c>a=rtcp-fb</c> attribute value.</summary>
    /// <param name="value">The attribute value, without the <c>a=rtcp-fb:</c> prefix.</param>
    /// <param name="entry">Receives the parsed entry.</param>
    /// <returns>True when the value is a well-formed rtcp-fb line.</returns>
    public static bool TryParse(string? value, out RtcpFeedbackEntry? entry)
    {
        entry = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var fields = value.Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 2)
        {
            return false;
        }

        int? pt = null;
        if (!string.Equals(fields[0], "*", StringComparison.Ordinal))
        {
            if (!int.TryParse(fields[0], NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
            {
                return false;
            }

            pt = parsed;
        }

        var parameter = fields.Length > 2 ? fields[2] : null;
        entry = new RtcpFeedbackEntry(pt, new RtcpFeedback(fields[1], parameter));
        return true;
    }

    /// <summary>Renders the value part of the <c>a=rtcp-fb</c> attribute.</summary>
    /// <returns>For example <c>96 nack pli</c> or <c>* transport-cc</c>.</returns>
    public string ToAttributeValue()
    {
        var pt = PayloadType?.ToString(CultureInfo.InvariantCulture) ?? "*";
        return pt + " " + Feedback;
    }

    /// <summary>Renders the complete attribute without a line terminator.</summary>
    /// <returns>For example <c>a=rtcp-fb:96 nack pli</c>.</returns>
    public override string ToString() => "a=rtcp-fb:" + ToAttributeValue();
}
