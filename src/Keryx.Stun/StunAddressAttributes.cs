using System.Net;
using System.Net.Sockets;
using Keryx.Core;

namespace Keryx.Stun;

/// <summary>
/// Base class for the transport-address attributes, whose value is a one-byte pad, a one-byte
/// address family (1 = IPv4, 2 = IPv6), a 16-bit port and a 4- or 16-byte address
/// (RFC 5389 sections 15.1 and 15.2).
/// </summary>
public abstract class StunAddressAttribute : StunAttribute
{
    private const byte FamilyIPv4 = 0x01;
    private const byte FamilyIPv6 = 0x02;

    private protected StunAddressAttribute(IPEndPoint endPoint)
    {
        ArgumentNullException.ThrowIfNull(endPoint);
        if (endPoint.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            throw new ArgumentException("Only IPv4 and IPv6 addresses can be carried in a STUN address attribute.", nameof(endPoint));
        }

        EndPoint = endPoint;
    }

    /// <summary>The transport address carried by the attribute.</summary>
    public IPEndPoint EndPoint { get; }

    /// <summary>True when the attribute's value is XOR-obfuscated with the magic cookie and transaction id.</summary>
    protected abstract bool IsXored { get; }

    internal override void WriteValue(ref ByteWriter writer, ReadOnlySpan<byte> transactionId)
    {
        var isIPv6 = EndPoint.AddressFamily == AddressFamily.InterNetworkV6;

        // A heap array rather than a stackalloc: ByteWriter is a ref struct whose WriteBytes
        // parameter is not declared `scoped`, so the compiler cannot prove a stack span would not
        // escape into it.
        var address = EndPoint.Address.GetAddressBytes();
        if (address.Length != (isIPv6 ? 16 : 4))
        {
            throw new ByteBufferException("Unexpected IP address length in a STUN address attribute.");
        }

        var port = (ushort)EndPoint.Port;
        if (IsXored)
        {
            Xor(ref port, address, transactionId);
        }

        writer.WriteU8(0);
        writer.WriteU8(isIPv6 ? FamilyIPv6 : FamilyIPv4);
        writer.WriteU16(port);
        writer.WriteBytes(address);
    }

    internal static IPEndPoint ReadValue(ReadOnlySpan<byte> value, bool xored, ReadOnlySpan<byte> transactionId)
    {
        var reader = new ByteReader(value);
        reader.Skip(1);
        var family = reader.ReadU8();
        var port = reader.ReadU16();
        var addressLength = family switch
        {
            FamilyIPv4 => 4,
            FamilyIPv6 => 16,
            _ => throw new StunFormatException($"Unknown STUN address family 0x{family:x2}."),
        };

        Span<byte> address = stackalloc byte[addressLength];
        reader.ReadBytes(addressLength).CopyTo(address);
        if (xored)
        {
            Xor(ref port, address, transactionId);
        }

        return new IPEndPoint(new IPAddress(address), port);
    }

    /// <summary>
    /// Applies the RFC 5389 section 15.2 XOR: the port against the top 16 bits of the magic
    /// cookie, an IPv4 address against the cookie, an IPv6 address against the cookie concatenated
    /// with the transaction id. The transform is its own inverse.
    /// </summary>
    private static void Xor(ref ushort port, Span<byte> address, ReadOnlySpan<byte> transactionId)
    {
        port ^= (ushort)(StunMessage.MagicCookie >> 16);

        Span<byte> mask = stackalloc byte[16];
        mask[0] = unchecked((byte)(StunMessage.MagicCookie >> 24));
        mask[1] = unchecked((byte)(StunMessage.MagicCookie >> 16));
        mask[2] = unchecked((byte)(StunMessage.MagicCookie >> 8));
        mask[3] = unchecked((byte)StunMessage.MagicCookie);
        if (address.Length > 4)
        {
            if (transactionId.Length != StunTransactionId.Length)
            {
                throw new ByteBufferException("An XOR-obfuscated IPv6 address needs the full 12-byte transaction id.");
            }

            transactionId.CopyTo(mask[4..]);
        }

        for (var i = 0; i < address.Length; i++)
        {
            address[i] ^= mask[i];
        }
    }
}

/// <summary>MAPPED-ADDRESS: the reflexive transport address, in the clear (RFC 5389 section 15.1).</summary>
public sealed class StunMappedAddressAttribute : StunAddressAttribute
{
    /// <summary>Creates the attribute for <paramref name="endPoint"/>.</summary>
    /// <param name="endPoint">The reflexive transport address.</param>
    public StunMappedAddressAttribute(IPEndPoint endPoint)
        : base(endPoint)
    {
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.MappedAddress;

    /// <inheritdoc />
    protected override bool IsXored => false;
}

/// <summary>
/// XOR-MAPPED-ADDRESS: the reflexive transport address obfuscated against the magic cookie and
/// transaction id so that NATs rewriting payloads cannot recognise it (RFC 5389 section 15.2).
/// </summary>
public sealed class StunXorMappedAddressAttribute : StunAddressAttribute
{
    /// <summary>Creates the attribute for <paramref name="endPoint"/>.</summary>
    /// <param name="endPoint">The reflexive transport address.</param>
    public StunXorMappedAddressAttribute(IPEndPoint endPoint)
        : base(endPoint)
    {
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.XorMappedAddress;

    /// <inheritdoc />
    protected override bool IsXored => true;
}

/// <summary>ALTERNATE-SERVER: a server the client should retry against (RFC 5389 section 15.11).</summary>
public sealed class StunAlternateServerAttribute : StunAddressAttribute
{
    /// <summary>Creates the attribute for <paramref name="endPoint"/>.</summary>
    /// <param name="endPoint">The alternate server's transport address.</param>
    public StunAlternateServerAttribute(IPEndPoint endPoint)
        : base(endPoint)
    {
    }

    /// <inheritdoc />
    public override StunAttributeType Type => StunAttributeType.AlternateServer;

    /// <inheritdoc />
    protected override bool IsXored => false;
}
