namespace Keryx.Sdp;

/// <summary>Direction attribute of an m-section, expressed from the owning endpoint's point of view.</summary>
public enum MediaDirection
{
    /// <summary><c>a=inactive</c>: neither sending nor receiving.</summary>
    Inactive = 0,

    /// <summary><c>a=sendonly</c>.</summary>
    SendOnly = 1,

    /// <summary><c>a=recvonly</c>.</summary>
    RecvOnly = 2,

    /// <summary><c>a=sendrecv</c>. This is the SDP default when no direction attribute is present.</summary>
    SendRecv = 3,
}

/// <summary>Parsing, rendering and offer/answer intersection helpers for <see cref="MediaDirection"/>.</summary>
public static class SdpDirection
{
    /// <summary>The direction assumed when an m-section carries no direction attribute.</summary>
    public const MediaDirection Default = MediaDirection.SendRecv;

    /// <summary>The four attribute names that encode a direction, in a stable order.</summary>
    internal static readonly string[] AttributeNames = ["sendrecv", "sendonly", "recvonly", "inactive"];

    /// <summary>Renders a direction as its SDP attribute name.</summary>
    /// <param name="direction">The direction.</param>
    /// <returns>One of <c>sendrecv</c>, <c>sendonly</c>, <c>recvonly</c>, <c>inactive</c>.</returns>
    public static string ToAttributeName(this MediaDirection direction) => direction switch
    {
        MediaDirection.SendRecv => "sendrecv",
        MediaDirection.SendOnly => "sendonly",
        MediaDirection.RecvOnly => "recvonly",
        _ => "inactive",
    };

    /// <summary>True when the owner of this direction transmits media.</summary>
    /// <param name="direction">The direction.</param>
    /// <returns>True for <see cref="MediaDirection.SendOnly"/> and <see cref="MediaDirection.SendRecv"/>.</returns>
    public static bool Sends(this MediaDirection direction) =>
        direction is MediaDirection.SendOnly or MediaDirection.SendRecv;

    /// <summary>True when the owner of this direction receives media.</summary>
    /// <param name="direction">The direction.</param>
    /// <returns>True for <see cref="MediaDirection.RecvOnly"/> and <see cref="MediaDirection.SendRecv"/>.</returns>
    public static bool Receives(this MediaDirection direction) =>
        direction is MediaDirection.RecvOnly or MediaDirection.SendRecv;

    /// <summary>Swaps send and receive, giving the same stream seen from the far end.</summary>
    /// <param name="direction">The direction.</param>
    /// <returns>The mirrored direction.</returns>
    public static MediaDirection Reverse(this MediaDirection direction) => direction switch
    {
        MediaDirection.SendOnly => MediaDirection.RecvOnly,
        MediaDirection.RecvOnly => MediaDirection.SendOnly,
        _ => direction,
    };

    /// <summary>Builds a direction from independent send and receive flags.</summary>
    /// <param name="sends">Whether the endpoint transmits.</param>
    /// <param name="receives">Whether the endpoint receives.</param>
    /// <returns>The matching direction.</returns>
    public static MediaDirection FromFlags(bool sends, bool receives) => (sends, receives) switch
    {
        (true, true) => MediaDirection.SendRecv,
        (true, false) => MediaDirection.SendOnly,
        (false, true) => MediaDirection.RecvOnly,
        _ => MediaDirection.Inactive,
    };

    /// <summary>
    /// Intersects an offered direction with the answer's direction and returns the result from the
    /// <em>offerer's</em> point of view. The answer direction is stated from the answerer's point of
    /// view, so it is mirrored before intersecting.
    /// </summary>
    /// <param name="offered">Direction written by the offerer.</param>
    /// <param name="answered">Direction written by the answerer.</param>
    /// <returns>What the offerer may actually send and receive.</returns>
    public static MediaDirection Negotiate(MediaDirection offered, MediaDirection answered) =>
        FromFlags(offered.Sends() && answered.Receives(), offered.Receives() && answered.Sends());

    /// <summary>Parses an SDP direction attribute name.</summary>
    /// <param name="name">Attribute name, for example <c>sendonly</c>.</param>
    /// <param name="direction">Receives the parsed direction.</param>
    /// <returns>True when <paramref name="name"/> is one of the four direction attributes.</returns>
    public static bool TryParse(string? name, out MediaDirection direction)
    {
        switch (name)
        {
            case "sendrecv":
                direction = MediaDirection.SendRecv;
                return true;
            case "sendonly":
                direction = MediaDirection.SendOnly;
                return true;
            case "recvonly":
                direction = MediaDirection.RecvOnly;
                return true;
            case "inactive":
                direction = MediaDirection.Inactive;
                return true;
            default:
                direction = Default;
                return false;
        }
    }
}
