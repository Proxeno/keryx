using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Keryx.Stun;
using Xunit;

namespace Keryx.Turn.Tests;

/// <summary>
/// TURN over TCP and TLS (RFC 5766 section 2.1): the framing that reassembles STUN and ChannelData
/// out of a byte stream, and the full allocation and relay flow over a TCP / TLS
/// <see cref="TestTurnServer"/>. The relayed transport address is still UDP on the server; only the
/// client-to-server leg changes.
/// </summary>
public sealed class TurnTcpTests
{
    [Fact]
    public void Reassembler_YieldsStunThenChannelData_FromAByteStreamDeliveredOneByteAtATime()
    {
        // A STUN message (already 4-byte aligned) followed by a ChannelData message whose 3-byte
        // payload forces a byte of TCP padding (RFC 5766 section 11.5).
        var stun = new StunMessage(StunClass.Request, StunMethod.Binding).Encode();
        var channelData = new byte[8];
        var channelLength = TurnChannelData.Encode(channelData, 0x4001, [1, 2, 3]);
        channelLength.Should().Be(7);

        var stream = new byte[stun.Length + channelData.Length];
        stun.CopyTo(stream, 0);
        channelData.CopyTo(stream, stun.Length);

        var reassembler = new TurnStreamReassembler();
        var messages = new List<byte[]>();

        // Deliver a single byte at a time: every intermediate state is an incomplete message.
        foreach (var b in stream)
        {
            reassembler.Append([b]);
            while (reassembler.TryReadMessage(out var message))
            {
                messages.Add(message.ToArray());
            }
        }

        messages.Should().HaveCount(2);
        messages[0].Should().Equal(stun);

        // The ChannelData message is yielded without its padding byte, and still decodes.
        messages[1].Should().HaveCount(7);
        TurnChannelData.TryDecode(messages[1], out var channel, out var payload).Should().BeTrue();
        channel.Should().Be(0x4001);
        payload.ToArray().Should().Equal(1, 2, 3);
    }

    [Fact]
    public void Reassembler_ReassemblesTwoMessagesArrivingInOneRead()
    {
        var first = new StunMessage(StunClass.Indication, StunMethod.Data).Encode();
        var second = new StunMessage(StunClass.Request, StunMethod.Allocate).Encode();
        var combined = new byte[first.Length + second.Length];
        first.CopyTo(combined, 0);
        second.CopyTo(combined, first.Length);

        var reassembler = new TurnStreamReassembler();
        reassembler.Append(combined);

        reassembler.TryReadMessage(out var a).Should().BeTrue();
        a.ToArray().Should().Equal(first);
        reassembler.TryReadMessage(out var b).Should().BeTrue();
        b.ToArray().Should().Equal(second);
        reassembler.TryReadMessage(out _).Should().BeFalse();
    }

    [Fact]
    public void Reassembler_WaitsForTheWholeMessageBeforeYielding()
    {
        var stun = new StunMessage(StunClass.Request, StunMethod.Binding).Encode();

        var reassembler = new TurnStreamReassembler();
        reassembler.Append(stun.AsSpan(0, stun.Length - 1));
        reassembler.TryReadMessage(out _).Should().BeFalse();

        reassembler.Append(stun.AsSpan(stun.Length - 1));
        reassembler.TryReadMessage(out var message).Should().BeTrue();
        message.ToArray().Should().Equal(stun);
    }

    [Fact]
    public void Reassembler_ThrowsOnAByteThatIsNeitherStunNorChannelData()
    {
        var reassembler = new TurnStreamReassembler();

        // 0x80 is RTP/RTCP territory (RFC 7983), never valid on a TURN control stream.
        reassembler.Append([0x80, 0, 0, 0]);
        var read = () => reassembler.TryReadMessage(out _);
        read.Should().Throw<TurnStreamException>();
    }

    [Fact]
    public async Task Tcp_AllocatesAndRelaysADatagramRoundTripThroughTheConnection()
    {
        using var server = new TestTurnServer(transport: TurnClientTransport.Tcp);
        using var peer = new TestPeer();
        var received = new List<(byte[] Data, IPEndPoint Peer)>();

        using var client = await TurnClient.ConnectAsync(
            server.EndPoint,
            server.Username,
            server.Password,
            TurnClientTransport.Tcp,
            TurnClientHarness.FastOptions(),
            cancellationToken: TestTimeout.Token);
        client.OnRelayedData += (data, from) =>
        {
            lock (received)
            {
                received.Add((data.ToArray(), from));
            }
        };

        var relayed = await client.AllocateAsync(TestTimeout.Token);
        relayed.Should().Be(server.RelayedEndPoint);
        server.UnauthenticatedAllocates.Should().Be(1);
        server.AuthenticatedAllocates.Should().Be(1);

        // Bind a channel, so both directions travel as ChannelData over TCP - the path that needs
        // the four-byte padding and reassembly.
        var channel = await client.BindChannelAsync(peer.EndPoint, TestTimeout.Token);
        channel.Should().BeInRange(StunChannelNumberAttribute.MinChannelNumber, StunChannelNumberAttribute.MaxChannelNumber);

        // Client -> peer.
        var inbound = peer.ReceiveAsync(TestTimeout.Token);
        client.SendTo([1, 2, 3, 4, 5], peer.EndPoint);
        var (toPeer, _) = await inbound;
        toPeer.Should().Equal(1, 2, 3, 4, 5);
        server.ChannelDataFromClient.Should().Be(1);

        // Peer -> client.
        peer.SendTo([9, 8, 7], relayed);
        (await TestTimeout.WaitForAsync(() =>
        {
            lock (received)
            {
                return received.Count > 0;
            }
        })).Should().BeTrue();

        lock (received)
        {
            received.Single().Data.Should().Equal(9, 8, 7);
            received.Single().Peer.Should().Be(peer.EndPoint);
        }

        server.ChannelDataToClient.Should().Be(1);
    }

    [Fact]
    public async Task Tcp_RelaysAViaSendIndicationWhenChannelDataIsDisabled()
    {
        using var server = new TestTurnServer(transport: TurnClientTransport.Tcp);
        using var peer = new TestPeer();
        var options = TurnClientHarness.FastOptions();
        options.UseChannelData = false;

        using var client = await TurnClient.ConnectAsync(
            server.EndPoint, server.Username, server.Password, TurnClientTransport.Tcp, options,
            cancellationToken: TestTimeout.Token);

        await client.AllocateAsync(TestTimeout.Token);
        await client.CreatePermissionAsync(peer.EndPoint, TestTimeout.Token);

        var inbound = peer.ReceiveAsync(TestTimeout.Token);
        client.SendTo([42], peer.EndPoint);
        var (toPeer, _) = await inbound;

        toPeer.Should().Equal(42);
        server.ChannelDataFromClient.Should().Be(0);
        server.RelayedToPeer.Should().Be(1);
    }

    [Fact]
    public async Task Tls_AllocatesAndRelaysOverAWrappedConnectionWithCertificatePinning()
    {
        using var server = new TestTurnServer(transport: TurnClientTransport.Tls);
        using var peer = new TestPeer();
        var received = new List<byte[]>();

        var pinned = server.Certificate!;
        var options = TurnClientHarness.FastOptions();

        // The self-signed test certificate is trusted by pinning its thumbprint, never by switching
        // validation off - the same hook a caller would use for a private CA.
        options.TlsCertificateValidationCallback = (_, certificate, _, _) =>
            certificate is X509Certificate2 presented && presented.Thumbprint == pinned.Thumbprint;

        using var client = await TurnClient.ConnectAsync(
            server.EndPoint, server.Username, server.Password, TurnClientTransport.Tls, options,
            tlsServerName: server.Realm,
            cancellationToken: TestTimeout.Token);
        client.OnRelayedData += (data, _) =>
        {
            lock (received)
            {
                received.Add(data.ToArray());
            }
        };

        var relayed = await client.AllocateAsync(TestTimeout.Token);
        relayed.Should().Be(server.RelayedEndPoint);

        await client.BindChannelAsync(peer.EndPoint, TestTimeout.Token);

        peer.SendTo([5, 5, 5], relayed);
        (await TestTimeout.WaitForAsync(() =>
        {
            lock (received)
            {
                return received.Count > 0;
            }
        })).Should().BeTrue();

        lock (received)
        {
            received.Single().Should().Equal(5, 5, 5);
        }
    }

    [Fact]
    public async Task Tls_RejectsAServerWhoseCertificateFailsValidation()
    {
        using var server = new TestTurnServer(transport: TurnClientTransport.Tls);
        var options = TurnClientHarness.FastOptions();

        // Standard validation (no pinning) cannot trust the self-signed certificate, so the connect
        // must fail rather than proceed insecurely.
        options.TlsCertificateValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.None;

        var connect = async () => await TurnClient.ConnectAsync(
            server.EndPoint, server.Username, server.Password, TurnClientTransport.Tls, options,
            tlsServerName: server.Realm,
            cancellationToken: TestTimeout.Token);

        await connect.Should().ThrowAsync<Exception>();
    }

    [Theory]
    [InlineData(TurnClientTransport.Udp)]
    [InlineData(TurnClientTransport.Tcp)]
    [InlineData(TurnClientTransport.Tls)]
    public void TurnServerOptions_ValidatesEveryTransport(TurnClientTransport transport)
    {
        var options = new TurnServerOptions("turn.example", 443, "user", "pass") { ClientTransport = transport };
        var validate = options.Validate;
        validate.Should().NotThrow();
    }

    [Fact]
    public async Task ConnectAsync_RejectsTheUdpTransport()
    {
        var connect = async () => await TurnClient.ConnectAsync(
            new IPEndPoint(IPAddress.Loopback, 3478), "u", "p", TurnClientTransport.Udp);

        await connect.Should().ThrowAsync<ArgumentException>();
    }
}
