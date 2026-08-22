namespace Keryx.Sdp;

/// <summary>
/// The <c>c=</c> line: <c>c=&lt;nettype&gt; &lt;addrtype&gt; &lt;connection-address&gt;</c>.
/// </summary>
/// <param name="NetworkType">Network type, always <c>IN</c> for WebRTC.</param>
/// <param name="AddressType">Address type, <c>IP4</c> or <c>IP6</c>.</param>
/// <param name="Address">
/// Connection address, kept verbatim so any <c>/ttl/count</c> suffix survives a round trip. WebRTC
/// offers use the placeholder <c>0.0.0.0</c>.
/// </param>
public sealed record SdpConnection(string NetworkType, string AddressType, string Address)
{
    /// <summary>The <c>c=IN IP4 0.0.0.0</c> placeholder every WebRTC m-section carries.</summary>
    public static SdpConnection WebRtcPlaceholder { get; } = new("IN", "IP4", "0.0.0.0");

    /// <summary>Parses the text following <c>c=</c>.</summary>
    /// <param name="text">The <c>c=</c> line body.</param>
    /// <returns>The parsed connection data.</returns>
    public static SdpConnection Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return new SdpConnection(
            parts.Length > 0 ? parts[0] : "IN",
            parts.Length > 1 ? parts[1] : "IP4",
            parts.Length > 2 ? parts[2] : "0.0.0.0");
    }

    /// <summary>Renders the connection without the leading <c>c=</c>.</summary>
    /// <returns>The three space-separated fields.</returns>
    public string ToLineValue() => string.Join(' ', NetworkType, AddressType, Address);

    /// <summary>Renders the complete <c>c=</c> line without a line terminator.</summary>
    /// <returns>For example <c>c=IN IP4 0.0.0.0</c>.</returns>
    public override string ToString() => "c=" + ToLineValue();
}
