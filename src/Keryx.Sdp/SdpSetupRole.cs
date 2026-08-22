namespace Keryx.Sdp;

/// <summary>The DTLS role advertised by <c>a=setup</c> (RFC 4145 / RFC 5763).</summary>
public enum SdpSetupRole
{
    /// <summary><c>a=setup:actpass</c>: the offerer accepts either role. Only valid in an offer.</summary>
    ActPass = 0,

    /// <summary><c>a=setup:active</c>: this endpoint opens the DTLS connection (acts as client).</summary>
    Active = 1,

    /// <summary><c>a=setup:passive</c>: this endpoint waits for the DTLS handshake (acts as server).</summary>
    Passive = 2,

    /// <summary><c>a=setup:holdconn</c>: connection is not established yet.</summary>
    HoldConn = 3,
}

/// <summary>Parsing and rendering helpers for <see cref="SdpSetupRole"/>.</summary>
public static class SdpSetup
{
    /// <summary>Renders a role as its <c>a=setup</c> value.</summary>
    /// <param name="role">The role.</param>
    /// <returns>One of <c>actpass</c>, <c>active</c>, <c>passive</c>, <c>holdconn</c>.</returns>
    public static string ToAttributeValue(this SdpSetupRole role) => role switch
    {
        SdpSetupRole.ActPass => "actpass",
        SdpSetupRole.Active => "active",
        SdpSetupRole.Passive => "passive",
        _ => "holdconn",
    };

    /// <summary>
    /// The role the local endpoint must take given the remote role. <c>actpass</c> from the remote
    /// side leaves the choice open and yields <see cref="SdpSetupRole.Active"/>.
    /// </summary>
    /// <param name="remote">The remote endpoint's advertised role.</param>
    /// <returns>The complementary local role.</returns>
    public static SdpSetupRole Complement(this SdpSetupRole remote) => remote switch
    {
        SdpSetupRole.Active => SdpSetupRole.Passive,
        SdpSetupRole.Passive => SdpSetupRole.Active,
        SdpSetupRole.ActPass => SdpSetupRole.Active,
        _ => SdpSetupRole.HoldConn,
    };

    /// <summary>Parses an <c>a=setup</c> value.</summary>
    /// <param name="value">The attribute value.</param>
    /// <param name="role">Receives the parsed role.</param>
    /// <returns>True when <paramref name="value"/> is a known role.</returns>
    public static bool TryParse(string? value, out SdpSetupRole role)
    {
        switch (value?.Trim())
        {
            case "actpass":
                role = SdpSetupRole.ActPass;
                return true;
            case "active":
                role = SdpSetupRole.Active;
                return true;
            case "passive":
                role = SdpSetupRole.Passive;
                return true;
            case "holdconn":
                role = SdpSetupRole.HoldConn;
                return true;
            default:
                role = SdpSetupRole.ActPass;
                return false;
        }
    }
}
