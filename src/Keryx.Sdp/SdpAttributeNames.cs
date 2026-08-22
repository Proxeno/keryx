namespace Keryx.Sdp;

/// <summary>Attribute names Keryx interprets. Exposed so callers can reach the raw attribute list.</summary>
public static class SdpAttributeNames
{
    /// <summary><c>a=group</c> (RFC 5888).</summary>
    public const string Group = "group";

    /// <summary><c>a=msid-semantic</c>.</summary>
    public const string MsidSemantic = "msid-semantic";

    /// <summary><c>a=mid</c>.</summary>
    public const string Mid = "mid";

    /// <summary><c>a=ice-ufrag</c>.</summary>
    public const string IceUfrag = "ice-ufrag";

    /// <summary><c>a=ice-pwd</c>.</summary>
    public const string IcePwd = "ice-pwd";

    /// <summary><c>a=ice-options</c>.</summary>
    public const string IceOptions = "ice-options";

    /// <summary><c>a=fingerprint</c>.</summary>
    public const string Fingerprint = "fingerprint";

    /// <summary><c>a=setup</c>.</summary>
    public const string Setup = "setup";

    /// <summary><c>a=rtcp</c>.</summary>
    public const string Rtcp = "rtcp";

    /// <summary><c>a=rtcp-mux</c>.</summary>
    public const string RtcpMux = "rtcp-mux";

    /// <summary><c>a=rtcp-rsize</c>.</summary>
    public const string RtcpReducedSize = "rtcp-rsize";

    /// <summary><c>a=rtpmap</c>.</summary>
    public const string RtpMap = "rtpmap";

    /// <summary><c>a=fmtp</c>.</summary>
    public const string Fmtp = "fmtp";

    /// <summary><c>a=rtcp-fb</c>.</summary>
    public const string RtcpFeedback = "rtcp-fb";

    /// <summary><c>a=ssrc</c>.</summary>
    public const string Ssrc = "ssrc";

    /// <summary><c>a=ssrc-group</c>.</summary>
    public const string SsrcGroup = "ssrc-group";

    /// <summary><c>a=msid</c>.</summary>
    public const string Msid = "msid";

    /// <summary><c>a=extmap</c>.</summary>
    public const string ExtMap = "extmap";

    /// <summary><c>a=extmap-allow-mixed</c>.</summary>
    public const string ExtMapAllowMixed = "extmap-allow-mixed";

    /// <summary><c>a=candidate</c>.</summary>
    public const string Candidate = "candidate";

    /// <summary><c>a=end-of-candidates</c>.</summary>
    public const string EndOfCandidates = "end-of-candidates";

    /// <summary><c>a=sctp-port</c>.</summary>
    public const string SctpPort = "sctp-port";

    /// <summary><c>a=max-message-size</c>.</summary>
    public const string MaxMessageSize = "max-message-size";

    /// <summary><c>a=cname</c> source attribute name used inside <c>a=ssrc</c> lines.</summary>
    public const string Cname = "cname";
}
