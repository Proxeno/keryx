using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Keryx.Ice;

/// <summary>
/// A one-shot multicast DNS resolver built on BCL sockets alone: it multicasts an A and an AAAA
/// query for a <c>&lt;name&gt;.local</c> host to <c>224.0.0.251:5353</c> (and, where the OS has an
/// IPv6 stack, to <c>[ff02::fb]:5353</c>) with the QU "unicast response requested" bit set, then
/// waits a short time for the first matching answer (RFC 6762).
/// </summary>
/// <remarks>
/// The resolver holds no state between calls and opens its sockets only while a query is in flight,
/// so nothing is bound until a <c>.local</c> candidate actually arrives. Any socket failure - a
/// network with no multicast route, a sandbox that forbids it - is swallowed and surfaced as a null
/// result, so resolution degrades gracefully to "unresolvable" rather than faulting the agent.
/// </remarks>
public sealed class MulticastMdnsResolver : IMdnsResolver
{
    private const int MdnsPort = 5353;
    private const ushort TypeA = 1;
    private const ushort TypeAaaa = 28;
    private const ushort ClassInUnicastResponse = 0x8001;

    private static readonly IPAddress MulticastV4 = IPAddress.Parse("224.0.0.251");
    private static readonly IPAddress MulticastV6 = IPAddress.Parse("ff02::fb");

    private readonly TimeSpan _timeout;

    /// <summary>Creates a resolver.</summary>
    /// <param name="timeout">
    /// How long to wait for an answer before giving up. Defaults to two seconds; mDNS on a healthy
    /// LAN answers in a few milliseconds, so a short bound keeps a missing name from stalling intake.
    /// </param>
    public MulticastMdnsResolver(TimeSpan? timeout = null)
    {
        var value = timeout ?? TimeSpan.FromSeconds(2);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, TimeSpan.Zero);
        _timeout = value;
    }

    /// <summary>A shared resolver with the default timeout, used when no resolver is configured.</summary>
    public static MulticastMdnsResolver Shared { get; } = new();

    /// <inheritdoc />
    public async Task<IPAddress?> ResolveAsync(string hostName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(hostName);

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linked.CancelAfter(_timeout);
        var token = linked.Token;

        var queries = new[] { BuildQuery(hostName, TypeA), BuildQuery(hostName, TypeAaaa) };

        var tasks = new List<Task<IPAddress?>>
        {
            QueryAsync(AddressFamily.InterNetwork, MulticastV4, queries, hostName, token),
        };
        if (Socket.OSSupportsIPv6)
        {
            tasks.Add(QueryAsync(AddressFamily.InterNetworkV6, MulticastV6, queries, hostName, token));
        }

        // The first family to produce an address wins; a family that only times out returns null and
        // is discarded, so an IPv4-only answer is not held up by the IPv6 wait and vice versa.
        while (tasks.Count > 0)
        {
            var completed = await Task.WhenAny(tasks).ConfigureAwait(false);
            tasks.Remove(completed);
            var address = await completed.ConfigureAwait(false);
            if (address is not null)
            {
                return address;
            }
        }

        return null;
    }

    private static async Task<IPAddress?> QueryAsync(
        AddressFamily family, IPAddress group, byte[][] queries, string hostName, CancellationToken token)
    {
        try
        {
            using var socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
            var anyAddress = family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any;
            socket.Bind(new IPEndPoint(anyAddress, 0));
            TrySetMulticastTtl(socket, family);

            var destination = new IPEndPoint(group, MdnsPort);
            foreach (var query in queries)
            {
                await socket.SendToAsync(query, SocketFlags.None, destination, token).ConfigureAwait(false);
            }

            var buffer = new byte[1500];
            EndPoint from = new IPEndPoint(anyAddress, 0);
            while (!token.IsCancellationRequested)
            {
                var result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, from, token).ConfigureAwait(false);
                if (TryReadAnswer(buffer.AsSpan(0, result.ReceivedBytes), hostName, out var address))
                {
                    return address;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // The deadline elapsed before an answer arrived.
        }
        catch (SocketException)
        {
            // No multicast route, or the environment forbids it; treated as unresolvable.
        }

        return null;
    }

    private static void TrySetMulticastTtl(Socket socket, AddressFamily family)
    {
        try
        {
            // RFC 6762 section 11: mDNS packets carry a TTL of 255. Best effort - some platforms
            // reject the option, which is harmless because a link-local send still reaches the LAN.
            var level = family == AddressFamily.InterNetworkV6 ? SocketOptionLevel.IPv6 : SocketOptionLevel.IP;
            socket.SetSocketOption(level, SocketOptionName.MulticastTimeToLive, 255);
        }
        catch (SocketException)
        {
        }
    }

    private static byte[] BuildQuery(string hostName, ushort queryType)
    {
        var labels = hostName.Split('.', StringSplitOptions.RemoveEmptyEntries);
        var size = 12; // header
        foreach (var label in labels)
        {
            size += 1 + Encoding.UTF8.GetByteCount(label);
        }

        size += 1 + 2 + 2; // root label + qtype + qclass

        var buffer = new byte[size];
        // ID 0, flags 0 (standard query), QDCOUNT 1, all other counts 0.
        buffer[5] = 1;

        var offset = 12;
        foreach (var label in labels)
        {
            var bytes = Encoding.UTF8.GetBytes(label);
            buffer[offset++] = (byte)bytes.Length;
            bytes.CopyTo(buffer, offset);
            offset += bytes.Length;
        }

        buffer[offset++] = 0; // root label
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset), queryType);
        offset += 2;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset), ClassInUnicastResponse);
        return buffer;
    }

    private static bool TryReadAnswer(ReadOnlySpan<byte> message, string hostName, out IPAddress? address)
    {
        address = null;
        if (message.Length < 12)
        {
            return false;
        }

        var questions = BinaryPrimitives.ReadUInt16BigEndian(message[4..]);
        var answers = BinaryPrimitives.ReadUInt16BigEndian(message[6..]);
        var offset = 12;

        for (var i = 0; i < questions; i++)
        {
            offset = SkipName(message, offset);
            offset += 4; // qtype + qclass
            if (offset > message.Length)
            {
                return false;
            }
        }

        for (var i = 0; i < answers; i++)
        {
            offset = ReadName(message, offset, out var name);
            if (offset + 10 > message.Length)
            {
                return false;
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(message[offset..]);
            var rdLength = BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 8)..]);
            offset += 10;
            if (offset + rdLength > message.Length)
            {
                return false;
            }

            if (string.Equals(name, hostName, StringComparison.OrdinalIgnoreCase))
            {
                if (type == TypeA && rdLength == 4)
                {
                    address = new IPAddress(message.Slice(offset, 4).ToArray());
                    return true;
                }

                if (type == TypeAaaa && rdLength == 16)
                {
                    address = new IPAddress(message.Slice(offset, 16).ToArray());
                    return true;
                }
            }

            offset += rdLength;
        }

        return false;
    }

    private static int SkipName(ReadOnlySpan<byte> message, int offset) => ReadName(message, offset, out _);

    /// <summary>
    /// Decodes a DNS name, following RFC 1035 compression pointers, and returns the offset of the
    /// byte after the name in the record stream (past the pointer for a compressed name).
    /// </summary>
    private static int ReadName(ReadOnlySpan<byte> message, int offset, out string name)
    {
        var builder = new StringBuilder();
        int? afterName = null;
        var guard = 0;

        while (offset >= 0 && offset < message.Length)
        {
            var length = message[offset];
            if (length == 0)
            {
                offset++;
                afterName ??= offset;
                break;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (offset + 1 >= message.Length)
                {
                    break;
                }

                var pointer = ((length & 0x3F) << 8) | message[offset + 1];
                afterName ??= offset + 2;
                offset = pointer;
                if (++guard > 128)
                {
                    break;
                }

                continue;
            }

            offset++;
            if (offset + length > message.Length)
            {
                break;
            }

            if (builder.Length > 0)
            {
                builder.Append('.');
            }

            builder.Append(Encoding.UTF8.GetString(message.Slice(offset, length)));
            offset += length;
        }

        name = builder.ToString();
        return afterName ?? offset;
    }
}
