using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using FluentAssertions;
using Xunit;

namespace Keryx.Core.Tests;

/// <summary>
/// Unit-tests the native fast-path logic of <see cref="BatchedDatagramSender"/> on any OS by forcing
/// the native marshalling code to run and swapping the real <c>sendmmsg(2)</c> for a fake syscall.
/// The fake decodes the fully marshalled mmsghdr/iovec/sockaddr the production code produced (so the
/// IPv4/IPv6 marshalling is checked byte-for-byte) and scripts the return values that drive the
/// partial-send, EINTR-retry, backpressure and error paths.
/// </summary>
public sealed class BatchedDatagramSenderNativeMarshallingTests
{
    private const int EIntr = 4;
    private const int EAgain = 11;
    private const int ENoBufs = 105;
    private const int EMsgSize = 90;

    [Fact]
    public void Marshals_IPv4_Destinations_ByteForByte()
    {
        using var socket = NewUdpSocket();
        var fake = new FakeBatchSyscall();
        using var sender = new BatchedDatagramSender(socket, fake);

        var p0 = new byte[] { 1, 2, 3, 4 };
        var p1 = new byte[] { 9, 8, 7 };
        var d0 = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 4321);
        var d1 = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 65535);

        fake.EnqueueSendAll();
        var sent = sender.Send([new Datagram(p0, d0), new Datagram(p1, d1)]);

        sent.Should().Be(2);
        fake.Decoded.Should().HaveCount(2);
        AssertIPv4(fake.Decoded[0], p0, d0);
        AssertIPv4(fake.Decoded[1], p1, d1);
    }

    [Fact]
    public void Marshals_IPv6_Destinations_ByteForByte()
    {
        using var socket = NewUdpSocket();
        var fake = new FakeBatchSyscall();
        using var sender = new BatchedDatagramSender(socket, fake);

        var payload = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
        var dest = new IPEndPoint(IPAddress.Parse("2001:db8::1234"), 9000);

        fake.EnqueueSendAll();
        sender.Send([new Datagram(payload, dest)]).Should().Be(1);

        var decoded = fake.Decoded.Single();
        decoded.NameLen.Should().Be(28u);
        decoded.Payload.Should().Equal(payload);

        // sockaddr_in6: family(2) port(2, net) flowinfo(4) addr(16) scope_id(4).
        BinaryPrimitives.ReadUInt16LittleEndian(decoded.Addr).Should().Be(10, "AF_INET6 on Linux is 10");
        BinaryPrimitives.ReadUInt16BigEndian(decoded.Addr.AsSpan(2)).Should().Be(9000);
        BinaryPrimitives.ReadUInt32LittleEndian(decoded.Addr.AsSpan(4)).Should().Be(0, "sin6_flowinfo");
        decoded.Addr.AsSpan(8, 16).ToArray().Should().Equal(dest.Address.GetAddressBytes());
        BinaryPrimitives.ReadUInt32LittleEndian(decoded.Addr.AsSpan(24)).Should().Be((uint)dest.Address.ScopeId);
    }

    [Fact]
    public void PartialSends_LoopUntilWholeBatchIsAccepted()
    {
        using var socket = NewUdpSocket();
        var fake = new FakeBatchSyscall();
        using var sender = new BatchedDatagramSender(socket, fake);

        // Kernel accepts the 5-message batch in dribs: 2, then 1, then the last 2.
        fake.EnqueueSend(2);
        fake.EnqueueSend(1);
        fake.EnqueueSend(2);

        var datagrams = MakeBatch(5);
        var sent = sender.Send(datagrams);

        sent.Should().Be(5);
        fake.OfferedVlens.Should().Equal([5u, 3u, 2u]); // each retry offers only the un-sent tail
        fake.Decoded.Should().HaveCount(5);
        for (var i = 0; i < 5; i++)
        {
            fake.Decoded[i].Payload.Should().Equal(datagrams[i].Payload.ToArray(),
                "datagrams are sent and observed in order across partial sends");
        }
    }

    [Fact]
    public void Eintr_IsRetried()
    {
        using var socket = NewUdpSocket();
        var fake = new FakeBatchSyscall();
        using var sender = new BatchedDatagramSender(socket, fake);

        fake.EnqueueError(EIntr); // Interrupted before anything went out.
        fake.EnqueueSend(2);
        fake.EnqueueError(EIntr);
        fake.EnqueueSend(1);

        sender.Send(MakeBatch(3)).Should().Be(3);
    }

    [Theory]
    [InlineData(EAgain)]
    [InlineData(ENoBufs)]
    public void Backpressure_ReturnsPrefixSent_WithoutThrowing(int errno)
    {
        using var socket = NewUdpSocket();
        var fake = new FakeBatchSyscall();
        using var sender = new BatchedDatagramSender(socket, fake);

        fake.EnqueueSend(2);      // Two go out...
        fake.EnqueueError(errno); // ...then the send buffer is full.

        var sent = sender.Send(MakeBatch(5));

        sent.Should().Be(2, "a short return signals the caller to retry the un-sent tail");
    }

    [Fact]
    public void NonTransientError_ThrowsSocketException_AfterSendingThePrefix()
    {
        using var socket = NewUdpSocket();
        var fake = new FakeBatchSyscall();
        using var sender = new BatchedDatagramSender(socket, fake);

        fake.EnqueueSend(1);         // First datagram goes out...
        fake.EnqueueError(EMsgSize); // ...then message 2 is rejected as oversized.

        var act = () => sender.Send(MakeBatch(4));

        act.Should().Throw<SocketException>();
    }

    [Fact]
    public void LargeBatch_IsChunkedAtUioMaxIov()
    {
        using var socket = NewUdpSocket();
        var fake = new FakeBatchSyscall();
        using var sender = new BatchedDatagramSender(socket, fake);

        // 2500 > UIO_MAXIOV (1024): expect chunks of 1024, 1024, 452.
        const int count = 2500;
        for (var i = 0; i < 3; i++)
        {
            fake.EnqueueSendAll();
        }

        var sent = sender.Send(MakeBatch(count));

        sent.Should().Be(count);
        fake.OfferedVlens.Should().Equal(1024u, 1024u, 452u);
        fake.Decoded.Should().HaveCount(count);
    }

    [Fact]
    public void GrowingThenShrinkingBatches_ReuseBuffersCorrectly()
    {
        using var socket = NewUdpSocket();
        var fake = new FakeBatchSyscall();
        using var sender = new BatchedDatagramSender(socket, fake);

        foreach (var size in (int[])[4, 64, 8, 64])
        {
            fake.EnqueueSendAll();
            var batch = MakeBatch(size);
            sender.Send(batch).Should().Be(size);
            fake.Decoded.Should().HaveCount(size);
            for (var i = 0; i < size; i++)
            {
                fake.Decoded[i].Payload.Should().Equal(batch[i].Payload.ToArray());
            }

            fake.Reset();
        }
    }

    [Fact]
    public void NativePath_RejectsNonIPEndPointDestination()
    {
        using var socket = NewUdpSocket();
        var fake = new FakeBatchSyscall();
        using var sender = new BatchedDatagramSender(socket, fake);

        fake.EnqueueSendAll();
        var act = () => sender.Send([new Datagram(new byte[] { 1 }, new DnsEndPoint("example.com", 80))]);

        act.Should().Throw<ArgumentException>();
    }

    private static void AssertIPv4(FakeBatchSyscall.DecodedMessage decoded, byte[] payload, IPEndPoint dest)
    {
        decoded.NameLen.Should().Be(16u);
        decoded.Payload.Should().Equal(payload);
        BinaryPrimitives.ReadUInt16LittleEndian(decoded.Addr).Should().Be(2, "AF_INET is 2");
        BinaryPrimitives.ReadUInt16BigEndian(decoded.Addr.AsSpan(2)).Should().Be((ushort)dest.Port);
        decoded.Addr.AsSpan(4, 4).ToArray().Should().Equal(dest.Address.GetAddressBytes());
    }

    private static Datagram[] MakeBatch(int count)
    {
        var datagrams = new Datagram[count];
        for (var i = 0; i < count; i++)
        {
            var payload = new byte[] { (byte)i, (byte)(i >> 8), 0xEE };
            datagrams[i] = new Datagram(payload, new IPEndPoint(IPAddress.Loopback, 20000 + (i % 1000)));
        }

        return datagrams;
    }

    private static Socket NewUdpSocket() =>
        new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

    /// <summary>
    /// A fake <c>sendmmsg</c> that decodes the marshalled messages it is handed and scripts the
    /// return values driving the partial-send / retry / backpressure / error paths.
    /// </summary>
    private sealed class FakeBatchSyscall : IDatagramBatchSyscall
    {
        private readonly Queue<Func<int, (int Result, int Error)>> _responses = new();

        public bool IsAvailable => true;

        public List<DecodedMessage> Decoded { get; } = [];

        public List<uint> OfferedVlens { get; } = [];

        /// <summary>Next call accepts all messages offered.</summary>
        public void EnqueueSendAll() => _responses.Enqueue(v => (v, 0));

        /// <summary>Next call accepts exactly <paramref name="count"/> messages.</summary>
        public void EnqueueSend(int count) => _responses.Enqueue(_ => (count, 0));

        /// <summary>Next call fails with <paramref name="errno"/> having sent nothing.</summary>
        public void EnqueueError(int errno) => _responses.Enqueue(_ => (-1, errno));

        public void Reset()
        {
            _responses.Clear();
            Decoded.Clear();
            OfferedVlens.Clear();
        }

        public int SendBatch(int fd, nint msgvec, uint vlen, out int errorCode)
        {
            OfferedVlens.Add(vlen);
            var response = _responses.Count > 0 ? _responses.Dequeue() : (v => (v, 0));
            var (result, error) = response((int)vlen);

            var toDecode = result >= 0 ? Math.Min(result, (int)vlen) : 0;
            for (var i = 0; i < toDecode; i++)
            {
                Decoded.Add(DecodeAt(msgvec, i));
            }

            errorCode = error;
            return result;
        }

        // Reconstruct one message from the native memory the production code marshalled. The payload
        // pin and native scratch are alive for the duration of this synchronous call.
        private static DecodedMessage DecodeAt(nint msgvec, int index)
        {
            var stride = Marshal.SizeOf<MMsgHdr>();
            var mm = Marshal.PtrToStructure<MMsgHdr>(msgvec + (index * stride));
            var hdr = mm.Hdr;

            var iov = Marshal.PtrToStructure<IoVec>(hdr.Iov);
            var payload = new byte[(int)iov.Len];
            if (payload.Length > 0)
            {
                Marshal.Copy(iov.Base, payload, 0, payload.Length);
            }

            var addr = new byte[hdr.NameLen];
            Marshal.Copy(hdr.Name, addr, 0, addr.Length);

            hdr.IovLen.Should().Be(1);
            return new DecodedMessage(payload, addr, hdr.NameLen);
        }

        internal sealed record DecodedMessage(byte[] Payload, byte[] Addr, uint NameLen);
    }
}
