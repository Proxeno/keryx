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

    /// <summary>Creates a candidate.</summary>
    /// <param name="foundation">The foundation; candidates of the same type, base and server share one.</param>
    /// <param name="component">The component id; always 1 for a bundled, rtcp-muxed session.</param>
    /// <param name="transport">The transport token, normally <c>udp</c>.</param>
    /// <param name="priority">The candidate priority from <see cref="IcePriority.Compute"/>.</param>
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

        var tokens = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length < 8 || !string.Equals(tokens[6], "typ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!int.TryParse(tokens[1], NumberStyles.None, CultureInfo.InvariantCulture, out var component)
            || component < 1
            || !uint.TryParse(tokens[3], NumberStyles.None, CultureInfo.InvariantCulture, out var priority)
            || !IPAddress.TryParse(tokens[4], out var address)
            || !int.TryParse(tokens[5], NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            || port > 65535
            || !TryParseType(tokens[7], out var type))
        {
            return false;
        }

        IPAddress? relatedAddress = null;
        int? relatedPort = null;
        List<KeyValuePair<string, string>>? extensions = null;

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

        candidate = new IceCandidate(
            tokens[0], component, tokens[2], priority, address, port, type, relatedAddress, relatedPort, extensions);
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
