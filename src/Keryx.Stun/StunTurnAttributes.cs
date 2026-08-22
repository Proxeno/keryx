using System.Net;
using System.Net.Sockets;
using Keryx.Core;

namespace Keryx.Stun;

/// <summary>
/// The transport protocols a TURN client can ask an allocation to relay, as carried in
/// REQUESTED-TRANSPORT (RFC 8656 section 18.8). The values are IANA protocol numbers.
/// </summary>
public enum TurnTransportProtocol : byte
{
    /// <summary>UDP (IANA protocol number 17); the only transport RFC 8656 defines for allocations.</summary>
    Udp = 17,

    /// <summary>TCP (IANA protocol number 6); used by the TURN-TCP extension of RFC 6062.</summary>
    Tcp = 6,
}

/// <summary>
/// CHANNEL-NUMBER: the channel a ChannelBind request is binding, as a 16-bit number followed by
/// two reserved bytes (RFC 8656 section 18.1).
/// </summary>
public sealed class StunChannelNumberAttribute : StunAttribute
{
    /// <summary>
    /// The lowest channel number a client may bind. RFC 8656 section 12 reserves 0x0000-0x3FFF and
    /// allocates 0x4000-0x4FFF for use; 0x5000-0xFFFF are reserved for future multiplexing.
    /// </summary>
    public const ushort MinChannelNumber = 0x4000;

    /// <summary>The highest channel number a client may bind (RFC 8656 section 12).</summary>
    public const ushort MaxChannelNumber = 0x4FFF;

    /// <summary>Creates the attribute.</summary>
    /// <param name="channelNumber">The channel number; must be in 0x4000-0x4FFF.</param>
    public StunChannelNumberAttribute(ushort channelNumber)
    {
        if (!IsValid(channelNumber))
        {
            throw new ArgumentOutOfRangeException(
                nameof(channelNumber),
                channelNumber,
                $"RFC 8656 section 12 only allows channel numbers 0x{MinChannelNumber:X4}-0x{MaxChannelNumber:X4}.");
        }

        ChannelNumber = channelNumber;
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.ChannelNumber;

    /// <summary>The channel number.</summary>
    public ushort ChannelNumber { get; }

    /// <summary>True when <paramref name="channelNumber"/> is in the range a client may bind.</summary>
    /// <param name="channelNumber">The channel number to test.</param>
    public static bool IsValid(ushort channelNumber)
        => channelNumber is >= MinChannelNumber and <= MaxChannelNumber;

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
    {
        writer.WriteU16(ChannelNumber);
        writer.WriteU16(0);
    }

    internal static StunChannelNumberAttribute ReadValue(ReadOnlySpan<byte> value)
    {
        var reader = new ByteReader(value);
        var channelNumber = reader.ReadU16();
        if (!IsValid(channelNumber))
        {
            throw new StunFormatException($"CHANNEL-NUMBER 0x{channelNumber:X4} is outside the range RFC 8656 section 12 allows.");
        }

        return new StunChannelNumberAttribute(channelNumber);
    }

    /// <inheritdoc />
    public override string ToString() => $"0x{ChannelNumber:X4}";
}

/// <summary>
/// LIFETIME: the number of seconds the server will keep an allocation alive without a refresh
/// (RFC 8656 section 18.2).
/// </summary>
public sealed class StunLifetimeAttribute : StunAttribute
{
    /// <summary>
    /// The allocation lifetime a server uses when the client asks for none, in seconds
    /// (RFC 8656 section 7.2).
    /// </summary>
    public const uint DefaultAllocationSeconds = 600;

    /// <summary>The lifetime of a permission, in seconds; not negotiable (RFC 8656 section 9).</summary>
    public const uint PermissionSeconds = 300;

    /// <summary>The lifetime of a channel binding, in seconds; not negotiable (RFC 8656 section 11).</summary>
    public const uint ChannelBindingSeconds = 600;

    /// <summary>Creates the attribute.</summary>
    /// <param name="seconds">The requested or granted lifetime in seconds; zero releases an allocation.</param>
    public StunLifetimeAttribute(uint seconds) => Seconds = seconds;

    /// <summary>Creates the attribute from a <see cref="TimeSpan"/>, rounding down to whole seconds.</summary>
    /// <param name="lifetime">The lifetime; must not be negative.</param>
    public StunLifetimeAttribute(TimeSpan lifetime)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(lifetime, TimeSpan.Zero);
        Seconds = (uint)Math.Min(lifetime.TotalSeconds, uint.MaxValue);
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.Lifetime;

    /// <summary>The lifetime in seconds.</summary>
    public uint Seconds { get; }

    /// <summary><see cref="Seconds"/> as a <see cref="TimeSpan"/>.</summary>
    public TimeSpan Lifetime => TimeSpan.FromSeconds(Seconds);

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
        => writer.WriteU32(Seconds);

    internal static StunLifetimeAttribute ReadValue(ReadOnlySpan<byte> value)
    {
        var reader = new ByteReader(value);
        return new StunLifetimeAttribute(reader.ReadU32());
    }

    /// <inheritdoc />
    public override string ToString() => $"{Seconds}s";
}

/// <summary>
/// XOR-PEER-ADDRESS: the transport address of a peer, obfuscated exactly like XOR-MAPPED-ADDRESS
/// (RFC 8656 section 18.3).
/// </summary>
public sealed class StunXorPeerAddressAttribute : StunAddressAttribute
{
    /// <summary>Creates the attribute for <paramref name="endPoint"/>.</summary>
    /// <param name="endPoint">The peer's transport address.</param>
    public StunXorPeerAddressAttribute(IPEndPoint endPoint)
        : base(endPoint)
    {
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.XorPeerAddress;

    /// <inheritdoc />
    protected override bool IsXored => true;
}

/// <summary>
/// XOR-RELAYED-ADDRESS: the transport address the server allocated on the relay, obfuscated
/// exactly like XOR-MAPPED-ADDRESS (RFC 8656 section 18.5).
/// </summary>
public sealed class StunXorRelayedAddressAttribute : StunAddressAttribute
{
    /// <summary>Creates the attribute for <paramref name="endPoint"/>.</summary>
    /// <param name="endPoint">The relayed transport address.</param>
    public StunXorRelayedAddressAttribute(IPEndPoint endPoint)
        : base(endPoint)
    {
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.XorRelayedAddress;

    /// <inheritdoc />
    protected override bool IsXored => true;
}

/// <summary>
/// DATA: the application payload carried by a Send or Data indication (RFC 8656 section 18.4).
/// </summary>
public sealed class StunDataAttribute : StunAttribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="value">The payload. Copied.</param>
    public StunDataAttribute(ReadOnlySpan<byte> value) => Value = value.ToArray();

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.Data;

    /// <summary>The payload, excluding the padding the attribute carries on the wire.</summary>
    public byte[] Value { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
        => writer.WriteBytes(Value);

    /// <inheritdoc />
    public override string ToString() => $"{Value.Length} byte(s)";
}

/// <summary>
/// REQUESTED-TRANSPORT: the transport protocol the allocation should relay, as a one-byte IANA
/// protocol number followed by three reserved bytes (RFC 8656 section 18.8).
/// </summary>
public sealed class StunRequestedTransportAttribute : StunAttribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="protocol">The transport protocol; RFC 8656 only defines UDP for Allocate.</param>
    public StunRequestedTransportAttribute(TurnTransportProtocol protocol = TurnTransportProtocol.Udp)
        => Protocol = protocol;

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.RequestedTransport;

    /// <summary>The requested transport protocol.</summary>
    public TurnTransportProtocol Protocol { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
    {
        writer.WriteU8((byte)Protocol);
        writer.WriteU24(0);
    }

    internal static StunRequestedTransportAttribute ReadValue(ReadOnlySpan<byte> value)
    {
        var reader = new ByteReader(value);
        return new StunRequestedTransportAttribute((TurnTransportProtocol)reader.ReadU8());
    }

    /// <inheritdoc />
    public override string ToString() => Protocol.ToString();
}

/// <summary>
/// DONT-FRAGMENT: asks the server to set the IPv4 DF bit on relayed datagrams. A zero-length flag
/// attribute (RFC 8656 section 18.9).
/// </summary>
public sealed class StunDontFragmentAttribute : StunAttribute
{
    /// <summary>The single shared instance; the attribute carries no state.</summary>
    public static readonly StunDontFragmentAttribute Instance = new();

    /// <summary>Creates the attribute. Prefer <see cref="Instance"/>.</summary>
    public StunDontFragmentAttribute()
    {
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.DontFragment;

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
    {
        // A flag attribute: type and length only, with a zero-length value.
    }
}

/// <summary>
/// REQUESTED-ADDRESS-FAMILY: the address family the relayed address should belong to, as a
/// one-byte family followed by three reserved bytes (RFC 8656 section 18.6).
/// </summary>
public sealed class StunRequestedAddressFamilyAttribute : StunAttribute
{
    /// <summary>The IPv4 family byte (RFC 8656 section 18.6).</summary>
    public const byte IPv4 = 0x01;

    /// <summary>The IPv6 family byte (RFC 8656 section 18.6).</summary>
    public const byte IPv6 = 0x02;

    /// <summary>Creates the attribute.</summary>
    /// <param name="family">The requested address family.</param>
    public StunRequestedAddressFamilyAttribute(AddressFamily family)
    {
        Family = family switch
        {
            AddressFamily.InterNetwork => IPv4,
            AddressFamily.InterNetworkV6 => IPv6,
            _ => throw new ArgumentException("Only IPv4 and IPv6 can be requested.", nameof(family)),
        };
    }

    private StunRequestedAddressFamilyAttribute(byte family) => Family = family;

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.RequestedAddressFamily;

    /// <summary>The family byte, <see cref="IPv4"/> or <see cref="IPv6"/>.</summary>
    public byte Family { get; }

    /// <summary>The requested family as a <see cref="AddressFamily"/>.</summary>
    public AddressFamily AddressFamily
        => Family == IPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
    {
        writer.WriteU8(Family);
        writer.WriteU24(0);
    }

    internal static StunRequestedAddressFamilyAttribute ReadValue(ReadOnlySpan<byte> value)
    {
        var reader = new ByteReader(value);
        var family = reader.ReadU8();
        if (family is not (IPv4 or IPv6))
        {
            throw new StunFormatException($"Unknown REQUESTED-ADDRESS-FAMILY value 0x{family:x2}.");
        }

        return new StunRequestedAddressFamilyAttribute(family);
    }
}

/// <summary>
/// EVEN-PORT: asks for an even relayed port, optionally reserving the next higher one. A one-byte
/// value whose most significant bit is the R flag (RFC 8656 section 18.7).
/// </summary>
public sealed class StunEvenPortAttribute : StunAttribute
{
    /// <summary>Creates the attribute.</summary>
    /// <param name="reserveNext">True to ask the server to also reserve the next higher port.</param>
    public StunEvenPortAttribute(bool reserveNext = false) => ReserveNext = reserveNext;

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.EvenPort;

    /// <summary>True when the R bit is set, reserving the next higher port for a later allocation.</summary>
    public bool ReserveNext { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
        => writer.WriteU8(ReserveNext ? (byte)0x80 : (byte)0x00);

    internal static StunEvenPortAttribute ReadValue(ReadOnlySpan<byte> value)
    {
        var reader = new ByteReader(value);
        return new StunEvenPortAttribute((reader.ReadU8() & 0x80) != 0);
    }
}

/// <summary>
/// RESERVATION-TOKEN: the eight-byte token identifying a port reserved by an earlier EVEN-PORT
/// request (RFC 8656 section 18.10).
/// </summary>
public sealed class StunReservationTokenAttribute : StunAttribute
{
    /// <summary>The token length in bytes.</summary>
    public const int TokenLength = 8;

    /// <summary>Creates the attribute.</summary>
    /// <param name="token">The eight-byte token. Copied.</param>
    public StunReservationTokenAttribute(ReadOnlySpan<byte> token)
    {
        if (token.Length != TokenLength)
        {
            throw new ArgumentException($"A RESERVATION-TOKEN is exactly {TokenLength} bytes.", nameof(token));
        }

        Token = token.ToArray();
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.ReservationToken;

    /// <summary>The eight-byte token.</summary>
    public byte[] Token { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
        => writer.WriteBytes(Token);

    internal static StunReservationTokenAttribute ReadValue(ReadOnlySpan<byte> value)
    {
        if (value.Length != TokenLength)
        {
            throw new StunFormatException($"A RESERVATION-TOKEN is exactly {TokenLength} bytes; got {value.Length}.");
        }

        return new StunReservationTokenAttribute(value);
    }
}
