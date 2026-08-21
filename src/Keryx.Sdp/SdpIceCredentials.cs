namespace Keryx.Sdp;

/// <summary>The <c>a=ice-ufrag</c> / <c>a=ice-pwd</c> pair for one ICE transport.</summary>
/// <param name="UsernameFragment">The <c>a=ice-ufrag</c> value.</param>
/// <param name="Password">The <c>a=ice-pwd</c> value.</param>
public sealed record SdpIceCredentials(string UsernameFragment, string Password);

/// <summary>How the offer builder groups m-sections onto transports.</summary>
public enum SdpBundlePolicy
{
    /// <summary>No <c>a=group:BUNDLE</c> line; every m-section negotiates its own transport.</summary>
    Disabled = 0,

    /// <summary>All m-sections listed in a single <c>a=group:BUNDLE</c>, sharing one transport.</summary>
    MaxBundle = 1,
}
