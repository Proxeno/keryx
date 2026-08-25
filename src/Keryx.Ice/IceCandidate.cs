using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Text;

namespace Keryx.Ice;

/// <summary>
/// One ICE candidate: a transport address the agent can be reached at, together with the metadata
/// SDP carries in a <c>candidate</c> attribute (RFC 8445 section 5.1, RFC 8839 section 5.1).
/// </summary>
/// <remarks>
/// <para>
/// The SDP syntax is
/// <c>foundation SP component SP transport SP priority SP address SP port SP "typ" SP type
/// *(SP name SP value)</c>. Keryx understands the <c>raddr</c> and <c>rport</c> extensions and
/// preserves every other trailing key/value pair verbatim, so Chrome's <c>generation</c>,
/// <c>ufrag</c>, <c>network-id</c>, <c>network-cost</c> and <c>tcptype</c> parameters survive a
/// parse/format round trip.
/// </para>
/// </remarks>
public sealed class IceCandidate : IEquatable<IceCandidate>
{
    /// <summary>The transport token for UDP candidates.</summary>
    public const string UdpTransport = "udp";

    /// <summary>The transport token for TCP candidates (RFC 6544).</summary>
    public const string TcpTransport = "tcp";

    /// <summary>
    /// The DNS suffix a browser gives an mDNS host candidate when it obfuscates a private address
    /// as <c>&lt;uuid&gt;.local</c> (draft-ietf-mmusic-mdns-ice-candidates). Such a connection
    /// address is a host name, not an <see cref="IPAddress"/>, so <see cref="TryParse"/> rejects it
    /// and <see cref="TryParseMdnsCandidate"/> recognises it instead.
    /// </summary>
    public const string MulticastDnsSuffix = ".local";

    /// <summary>Creates a candidate.</summary>
    /// <param name="foundation">The foundation; candidates of the same type, base and server share one.</param>
    /// <param name="component">The component id; always 1 for a bundled, rtcp-muxed session.</param>
    /// <param name="transport">The transport token, normally <c>udp</c>.</param>
    /// <param name="priority">The candidate priority from <see cref="IcePriority.Compute(IceCandidateType, int, int)"/>.</param>
    /// <param name="address">The transport address.</param>
    /// <param name="port">The transport port.</param>
    /// <param name="type">How the address was learned.</param>
    /// <param name="relatedAddress">For reflexive and relayed candidates, the base address.</param>
    /// <param name="relatedPort">For reflexive and relayed candidates, the base port.</param>
    /// <param name="extensions">Trailing key/value pairs to preserve, in order.</param>
    public IceCandidate(
        string foundation,
        int component,
        string transport,
        uint priority,
        IPAddress address,
        int port,
        IceCandidateType type,
        IPAddress? relatedAddress = null,
        int? relatedPort = null,
        IEnumerable<KeyValuePair<string, string>>? extensions = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(foundation);
        ArgumentException.ThrowIfNullOrEmpty(transport);
        ArgumentNullException.ThrowIfNull(address);
        ArgumentOutOfRangeException.ThrowIfLessThan(component, 1);
        ArgumentOutOfRangeException.ThrowIfNegative(port);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);

        Foundation = foundation;
        Component = component;
        Transport = transport;
        Priority = priority;
        Address = address;
        Port = port;
        Type = type;
        RelatedAddress = relatedAddress;
        RelatedPort = relatedPort;
        Extensions = extensions is null ? [] : [.. extensions];
        EndPoint = new IPEndPoint(address, port);
    }

    /// <summary>The foundation string; pairs with equal foundations are frozen and unfrozen together.</summary>
    public string Foundation { get; }

    /// <summary>The component id. Keryx only produces component 1 (BUNDLE with rtcp-mux).</summary>
    public int Component { get; }

    /// <summary>The transport token as written in SDP, for example <c>udp</c> or <c>UDP</c>.</summary>
    public string Transport { get; }

    /// <summary>True when <see cref="Transport"/> names UDP, ignoring case.</summary>
    public bool IsUdp => string.Equals(Transport, UdpTransport, StringComparison.OrdinalIgnoreCase);

    /// <summary>True when <see cref="Transport"/> names TCP, ignoring case (RFC 6544).</summary>
    public bool IsTcp => string.Equals(Transport, TcpTransport, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The RFC 6544 <c>tcptype</c> of a TCP candidate (<c>passive</c>, <c>active</c> or <c>so</c>),
    /// read from the preserved extensions, or null for a UDP candidate or a TCP candidate without one.
    /// </summary>
    public string? TcpType
    {
        get
        {
            foreach (var (name, value) in Extensions)
            {
                if (string.Equals(name, "tcptype", StringComparison.OrdinalIgnoreCase))
                {
                    return value;
                }
            }

            return null;
        }
    }

    /// <summary>The candidate priority (RFC 8445 section 5.1.2.1).</summary>
    public uint Priority { get; }

    /// <summary>The transport address.</summary>
    public IPAddress Address { get; }

    /// <summary>The transport port.</summary>
    public int Port { get; }

    /// <summary><see cref="Address"/> and <see cref="Port"/> as an endpoint.</summary>
    public IPEndPoint EndPoint { get; }

    /// <summary>How the address was learned.</summary>
    public IceCandidateType Type { get; }

    /// <summary>The <c>raddr</c> value for reflexive and relayed candidates, otherwise null.</summary>
    public IPAddress? RelatedAddress { get; }

    /// <summary>The <c>rport</c> value for reflexive and relayed candidates, otherwise null.</summary>
    public int? RelatedPort { get; }

    /// <summary>Trailing key/value pairs preserved verbatim, in the order they appeared.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Extensions { get; }

    /// <summary>
    /// The interface preference this candidate was gathered with. Not carried in SDP; used to
    /// derive the PRIORITY attribute of connectivity checks.
    /// </summary>
    internal int LocalPreference { get; init; } = IcePriority.MaxLocalPreference;

    /// <summary>The SDP token for <paramref name="type"/>: <c>host</c>, <c>srflx</c>, <c>prflx</c> or <c>relay</c>.</summary>
    /// <param name="type">The candidate type.</param>
    public static string TypeToken(IceCandidateType type) => type switch
    {
        IceCandidateType.Host => "host",
        IceCandidateType.ServerReflexive => "srflx",
        IceCandidateType.PeerReflexive => "prflx",
        IceCandidateType.Relayed => "relay",
        _ => throw new ArgumentOutOfRangeException(nameof(type)),
    };

    /// <summary>
    /// Parses an SDP candidate attribute. Accepts an optional <c>a=</c> prefix and an optional
    /// <c>candidate:</c> prefix, so both an SDP line and a bare attribute value are valid input.
    /// </summary>
    /// <param name="value">The attribute to parse.</param>
    /// <returns>The parsed candidate.</returns>
    /// <exception cref="FormatException">The attribute is not valid candidate syntax.</exception>
    public static IceCandidate Parse(string value)
        => TryParse(value, out var candidate)
            ? candidate
            : throw new FormatException($"'{value}' is not a valid SDP candidate attribute.");

    /// <summary>Parses an SDP candidate attribute, returning false instead of throwing.</summary>
    /// <param name="value">The attribute to parse; may carry an <c>a=</c> and/or <c>candidate:</c> prefix.</param>
    /// <param name="candidate">The parsed candidate on success.</param>
    /// <returns>True when <paramref name="value"/> was valid candidate syntax.</returns>
    public static bool TryParse(string? value, [NotNullWhen(true)] out IceCandidate? candidate)
    {
        candidate = null;
        if (!TryTokenize(value, out var tokens)
            || !IPAddress.TryParse(tokens[4], out var address)
            || !TryParseFields(
                tokens, out var component, out var priority, out var port, out var type,
                out var relatedAddress, out var relatedPort, out var extensions))
        {
            return false;
        }

        candidate = new IceCandidate(
            tokens[0], component, tokens[2], priority, address, port, type, relatedAddress, relatedPort, extensions);
        return true;
    }

    /// <summary>
    /// Recognises a candidate whose connection address is an mDNS <c>&lt;name&gt;.local</c> host
    /// name rather than an <see cref="IPAddress"/>. Browsers obfuscate host candidates this way by
    /// default, and because the address token is not an IP <see cref="TryParse"/> rejects the line;
    /// this method accepts it, yielding the host name to resolve and a factory that rebuilds the
    /// candidate once resolution produces an address.
    /// </summary>
    /// <param name="value">The attribute to parse; may carry an <c>a=</c> and/or <c>candidate:</c> prefix.</param>
    /// <param name="hostName">On success, the <c>.local</c> host name to resolve.</param>
    /// <param name="resolve">On success, a factory that builds the candidate from a resolved address.</param>
    /// <returns>True when <paramref name="value"/> is a well-formed candidate carrying an mDNS host name.</returns>
    public static bool TryParseMdnsCandidate(
        string? value,
        [NotNullWhen(true)] out string? hostName,
        [NotNullWhen(true)] out Func<IPAddress, IceCandidate>? resolve)
    {
        hostName = null;
        resolve = null;
        if (!TryTokenize(value, out var tokens))
        {
            return false;
        }

        var name = tokens[4];
        if (name.Length <= MulticastDnsSuffix.Length
            || !name.EndsWith(MulticastDnsSuffix, StringComparison.OrdinalIgnoreCase)
            || IPAddress.TryParse(name, out _))
        {
            return false;
        }

        if (!TryParseFields(
            tokens, out var component, out var priority, out var port, out var type,
            out var relatedAddress, out var relatedPort, out var extensions))
        {
            return false;
        }

        var foundation = tokens[0];
        var transport = tokens[2];
        hostName = name;
        resolve = address => new IceCandidate(
            foundation, component, transport, priority, address, port, type, relatedAddress, relatedPort, extensions);
        return true;
    }

    /// <summary>Strips the optional prefixes and splits the attribute, enforcing the <c>typ</c> anchor.</summary>
    private static bool TryTokenize(string? value, [NotNullWhen(true)] out string[]? tokens)
    {
        tokens = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var text = value.Trim();
        if (text.StartsWith("a=", StringComparison.Ordinal))
        {
            text = text[2..];
        }

        if (text.StartsWith("candidate:", StringComparison.OrdinalIgnoreCase))
        {
            text = text["candidate:".Length..];
        }

        var split = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (split.Length < 8 || !string.Equals(split[6], "typ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        tokens = split;
        return true;
    }

    /// <summary>
    /// Parses every field except the foundation, transport token and connection address (tokens 0,
    /// 2 and 4), which the callers handle: <see cref="TryParse"/> requires an IP address in token 4,
    /// <see cref="TryParseMdnsCandidate"/> accepts an mDNS host name there.
    /// </summary>
    private static bool TryParseFields(
        string[] tokens,
        out int component,
        out uint priority,
        out int port,
        out IceCandidateType type,
        out IPAddress? relatedAddress,
        out int? relatedPort,
        out List<KeyValuePair<string, string>>? extensions)
    {
        component = 0;
        priority = 0;
        port = 0;
        type = default;
        relatedAddress = null;
        relatedPort = null;
        extensions = null;

        if (!int.TryParse(tokens[1], NumberStyles.None, CultureInfo.InvariantCulture, out component)
            || component < 1
            || !uint.TryParse(tokens[3], NumberStyles.None, CultureInfo.InvariantCulture, out priority)
            || !int.TryParse(tokens[5], NumberStyles.None, CultureInfo.InvariantCulture, out port)
            || port > 65535
            || !TryParseType(tokens[7], out type))
        {
            return false;
        }

        for (var i = 8; i + 1 < tokens.Length; i += 2)
        {
            var name = tokens[i];
            var extensionValue = tokens[i + 1];
            if (string.Equals(name, "raddr", StringComparison.OrdinalIgnoreCase))
            {
                if (!IPAddress.TryParse(extensionValue, out relatedAddress))
                {
                    return false;
                }
            }
            else if (string.Equals(name, "rport", StringComparison.OrdinalIgnoreCase))
            {
                if (!int.TryParse(extensionValue, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedPort)
                    || parsedPort > 65535)
                {
                    return false;
                }

                relatedPort = parsedPort;
            }
            else
            {
                (extensions ??= []).Add(new KeyValuePair<string, string>(name, extensionValue));
            }
        }

        return true;
    }

    /// <summary>
    /// Formats the candidate as an SDP attribute value including the <c>candidate:</c> prefix, for
    /// example <c>candidate:2905311565 1 udp 2122260223 192.168.1.7 61042 typ host generation 0</c>.
    /// </summary>
    public string ToAttributeString() => Format(withPrefix: true);

    /// <summary>Formats the candidate without the <c>candidate:</c> prefix.</summary>
    public string ToValueString() => Format(withPrefix: false);

    /// <summary>Formats the candidate as a complete SDP line, <c>a=candidate:...</c>.</summary>
    public string ToSdpLine() => "a=" + Format(withPrefix: true);

    /// <inheritdoc />
    public override string ToString() => ToAttributeString();

    private string Format(bool withPrefix)
    {
        var builder = new StringBuilder(96);
        if (withPrefix)
        {
            builder.Append("candidate:");
        }

        builder.Append(Foundation).Append(' ')
            .Append(Component.ToString(CultureInfo.InvariantCulture)).Append(' ')
            .Append(Transport).Append(' ')
            .Append(Priority.ToString(CultureInfo.InvariantCulture)).Append(' ')
            .Append(Address.ToString()).Append(' ')
            .Append(Port.ToString(CultureInfo.InvariantCulture))
            .Append(" typ ").Append(TypeToken(Type));

        if (RelatedAddress is not null)
        {
            builder.Append(" raddr ").Append(RelatedAddress.ToString());
        }

        if (RelatedPort is { } relatedPort)
        {
            builder.Append(" rport ").Append(relatedPort.ToString(CultureInfo.InvariantCulture));
        }

        foreach (var (name, value) in Extensions)
        {
            builder.Append(' ').Append(name).Append(' ').Append(value);
        }

        return builder.ToString();
    }

    private static bool TryParseType(string token, out IceCandidateType type)
    {
        switch (token.ToLowerInvariant())
        {
            case "host":
                type = IceCandidateType.Host;
                return true;
            case "srflx":
                type = IceCandidateType.ServerReflexive;
                return true;
            case "prflx":
                type = IceCandidateType.PeerReflexive;
                return true;
            case "relay":
                type = IceCandidateType.Relayed;
                return true;
            default:
                type = default;
                return false;
        }
    }

    /// <summary>
    /// Two candidates are equal when they name the same transport address, component, transport
    /// and type; foundation, priority and extensions are ignored, matching how RFC 8445
    /// section 5.1.3 de-duplicates a candidate list.
    /// </summary>
    /// <param name="other">The candidate to compare with.</param>
    public bool Equals(IceCandidate? other)
        => other is not null
           && Component == other.Component
           && Type == other.Type
           && Port == other.Port
           && Address.Equals(other.Address)
           && string.Equals(Transport, other.Transport, StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as IceCandidate);

    /// <inheritdoc />
    public override int GetHashCode()
        => HashCode.Combine(Component, Type, Port, Address, Transport.ToLowerInvariant());
}
