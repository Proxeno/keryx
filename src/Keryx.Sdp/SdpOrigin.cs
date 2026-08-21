using System.Globalization;
using System.Security.Cryptography;

namespace Keryx.Sdp;

/// <summary>
/// The <c>o=</c> line: <c>o=&lt;username&gt; &lt;sess-id&gt; &lt;sess-version&gt; &lt;nettype&gt;
/// &lt;addrtype&gt; &lt;unicast-address&gt;</c>.
/// </summary>
/// <param name="Username">Originating user, or <c>-</c> when not supplied. WebRTC always uses <c>-</c>.</param>
/// <param name="SessionId">
/// Session identifier. Kept as text so arbitrarily large or zero-padded values survive a round trip;
/// WebRTC uses a random 64-bit value (see <see cref="NewSessionId"/>).
/// </param>
/// <param name="SessionVersion">Session version, incremented on each renegotiation.</param>
/// <param name="NetworkType">Network type, always <c>IN</c> for WebRTC.</param>
/// <param name="AddressType">Address type, <c>IP4</c> or <c>IP6</c>.</param>
/// <param name="UnicastAddress">Origin address. WebRTC uses the placeholder <c>127.0.0.1</c>.</param>
public sealed record SdpOrigin(
    string Username,
    string SessionId,
    string SessionVersion,
    string NetworkType,
    string AddressType,
    string UnicastAddress)
{
    /// <summary>A neutral origin used when none has been supplied.</summary>
    public static SdpOrigin Default { get; } = new("-", "0", "0", "IN", "IP4", "127.0.0.1");

    /// <summary>
    /// Generates a random session identifier in the range accepted by browsers: a positive 63-bit
    /// value, matching Chrome's <c>o=</c> line convention.
    /// </summary>
    /// <returns>The identifier rendered in invariant decimal.</returns>
    public static string NewSessionId()
    {
        Span<byte> bytes = stackalloc byte[8];
        RandomNumberGenerator.Fill(bytes);
        var value = BitConverter.ToUInt64(bytes) & 0x7FFF_FFFF_FFFF_FFFFUL;
        return value.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>Parses the text following <c>o=</c>. Missing trailing fields fall back to defaults.</summary>
    /// <param name="text">The <c>o=</c> line body.</param>
    /// <returns>The parsed origin.</returns>
    public static SdpOrigin Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return new SdpOrigin(
            parts.Length > 0 ? parts[0] : "-",
            parts.Length > 1 ? parts[1] : "0",
            parts.Length > 2 ? parts[2] : "0",
            parts.Length > 3 ? parts[3] : "IN",
            parts.Length > 4 ? parts[4] : "IP4",
            parts.Length > 5 ? parts[5] : "127.0.0.1");
    }

    /// <summary>Renders the origin without the leading <c>o=</c>.</summary>
    /// <returns>The six space-separated fields.</returns>
    public string ToLineValue() =>
        string.Join(' ', Username, SessionId, SessionVersion, NetworkType, AddressType, UnicastAddress);

    /// <summary>Renders the complete <c>o=</c> line without a line terminator.</summary>
    /// <returns>For example <c>o=- 12345 2 IN IP4 127.0.0.1</c>.</returns>
    public override string ToString() => "o=" + ToLineValue();
}
