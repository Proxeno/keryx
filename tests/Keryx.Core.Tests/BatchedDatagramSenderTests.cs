using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using Xunit;

namespace Keryx.Core.Tests;

/// <summary>
/// Functional tests for <see cref="BatchedDatagramSender"/> over a real UDP socket. On the CI/dev
/// host (macOS/Windows) these exercise the managed <see cref="Socket.SendTo(ReadOnlySpan{byte}, SocketFlags, EndPoint)"/>
/// fallback end to end; on Linux they run over the native <c>sendmmsg(2)</c> path — same public
/// contract either way. The native marshalling internals are unit-tested separately with a seam in
/// <see cref="BatchedDatagramSenderNativeMarshallingTests"/>.
/// </summary>
public sealed class BatchedDatagramSenderTests
{
    [Fact]
    public void EmptyBatch_SendsNothing()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        using var sender = new BatchedDatagramSender(socket);

        sender.Send(ReadOnlySpan<Datagram>.Empty).Should().Be(0);
    }

    [Fact]
    public void Send_AfterDispose_Throws()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        var sender = new BatchedDatagramSender(socket);
        sender.Dispose();

        var act = () => sender.Send(ReadOnlySpan<Datagram>.Empty);

        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Dispose_IsIdempotent_AndLeavesSocketOpen()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var sender = new BatchedDatagramSender(socket);

        sender.Dispose();
        sender.Dispose(); // Second call is a no-op.

        socket.IsBound.Should().BeTrue("the sender does not own the socket");
    }

    [Fact]
    public void NativeBatchSendSupported_MatchesPlatform()
    {
        // sendmmsg(2) is Linux-only; the symbol resolves on every supported Linux runtime image.
        BatchedDatagramSender.NativeBatchSendSupported.Should().Be(OperatingSystem.IsLinux());
    }

    [Fact]
    public void UsesNativeBatchSend_MatchesPlatform()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        using var sender = new BatchedDatagramSender(socket);

        sender.UsesNativeBatchSend.Should().Be(OperatingSystem.IsLinux());
    }

    [Theory]
    [InlineData(1)]
    [InlineData(8)]
    [InlineData(32)]
    public void Send_Batch_AllDatagramsArriveAtCorrectDestinationsWithCorrectPayloads(int batch)
    {
        // Distinct loopback receivers model fan-out: each datagram in the batch goes to its own
        // destination and carries a payload that encodes which receiver should get it.
        var receivers = new Socket[batch];
        var dests = new IPEndPoint[batch];
        var payloads = new byte[batch][];
        try
        {
            for (var i = 0; i < batch; i++)
            {
                var r = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
                {
                    ReceiveBufferSize = 1 << 20,
                    ReceiveTimeout = 5000,
                };
                r.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                receivers[i] = r;
                dests[i] = (IPEndPoint)r.LocalEndPoint!;
                payloads[i] = MakePayload(i, 16 + i);
            }

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            using var sender = new BatchedDatagramSender(socket);

            var datagrams = new Datagram[batch];
            for (var i = 0; i < batch; i++)
            {
                datagrams[i] = new Datagram(payloads[i], dests[i]);
            }

            var sent = sender.Send(datagrams);

            sent.Should().Be(batch);
            for (var i = 0; i < batch; i++)
            {
                var buffer = new byte[2048];
                var n = receivers[i].Receive(buffer);
                buffer.AsSpan(0, n).ToArray().Should().Equal(payloads[i],
                    $"receiver {i} must get exactly the payload addressed to it");
            }
        }
        finally
        {
            foreach (var r in receivers)
            {
                r?.Dispose();
            }
        }
    }

    [Fact]
    public void Send_RepeatedBatches_ReuseSenderWithoutLeaking()
    {
        using var receiver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
        {
            ReceiveBufferSize = 1 << 20,
            ReceiveTimeout = 5000,
        };
        receiver.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var dest = (IPEndPoint)receiver.LocalEndPoint!;

        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        using var sender = new BatchedDatagramSender(socket);

        const int rounds = 5;
        for (var round = 0; round < rounds; round++)
        {
            var payload = MakePayload(round, 24);
            sender.Send([new Datagram(payload, dest)]).Should().Be(1);

            var buffer = new byte[2048];
            var n = receiver.Receive(buffer);
            buffer.AsSpan(0, n).ToArray().Should().Equal(payload);
        }
    }

    private static byte[] MakePayload(int seed, int length)
    {
        var payload = new byte[length];
        for (var i = 0; i < length; i++)
        {
            payload[i] = (byte)((seed * 31) + i);
        }

        return payload;
    }
}
