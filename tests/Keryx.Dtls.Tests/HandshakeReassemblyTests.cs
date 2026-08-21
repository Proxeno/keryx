using System.Security.Cryptography;
using FluentAssertions;
using Keryx.Core;
using Xunit;

namespace Keryx.Dtls.Tests;

public class HandshakeReassemblyTests
{
    [Fact]
    public void An_unfragmented_message_round_trips()
    {
        var body = RandomNumberGenerator.GetBytes(64);
        var message = HandshakeMessage.Serialize(HandshakeType.ServerHello, 3, body);

        var reassembler = new HandshakeReassembler();
        reassembler.Reset(3);
        reassembler.AddRecord(message, out var retransmission).Should().BeTrue();
        retransmission.Should().BeFalse();

        reassembler.TryTakeNext(out var taken).Should().BeTrue();
        taken.Type.Should().Be(HandshakeType.ServerHello);
        taken.MessageSeq.Should().Be(3);
        taken.Body.Should().Equal(body);
        taken.ToTranscriptBytes().Should().Equal(message);
    }

    [Fact]
    public void A_message_larger_than_4kb_reassembles_from_out_of_order_fragments()
    {
        var body = RandomNumberGenerator.GetBytes(5000);
        var fragments = Fragment(HandshakeType.Certificate, messageSeq: 1, body, fragmentSize: 400);
        fragments.Should().HaveCountGreaterThan(12);

        var reassembler = new HandshakeReassembler();
        reassembler.Reset(1);

        // Deliver in reverse order, and duplicate one fragment for good measure.
        foreach (var fragment in fragments.AsEnumerable().Reverse())
        {
            reassembler.AddRecord(fragment, out _);
        }

        reassembler.AddRecord(fragments[3], out _);

        reassembler.TryTakeNext(out var message).Should().BeTrue();
        message.Type.Should().Be(HandshakeType.Certificate);
        message.Body.Should().Equal(body);
    }

    [Fact]
    public void Overlapping_fragments_reassemble_correctly()
    {
        var body = RandomNumberGenerator.GetBytes(1000);
        var reassembler = new HandshakeReassembler();
        reassembler.Reset(0);

        reassembler.AddRecord(MakeFragment(HandshakeType.Certificate, 0, body, 0, 600), out _);
        reassembler.AddRecord(MakeFragment(HandshakeType.Certificate, 0, body, 400, 600), out _);

        reassembler.TryTakeNext(out var message).Should().BeTrue();
        message.Body.Should().Equal(body);
    }

    [Fact]
    public void An_incomplete_message_is_not_delivered()
    {
        var body = RandomNumberGenerator.GetBytes(1000);
        var reassembler = new HandshakeReassembler();
        reassembler.Reset(0);

        reassembler.AddRecord(MakeFragment(HandshakeType.Certificate, 0, body, 0, 500), out _);
        reassembler.TryTakeNext(out _).Should().BeFalse();

        reassembler.AddRecord(MakeFragment(HandshakeType.Certificate, 0, body, 500, 499), out _);
        reassembler.TryTakeNext(out _).Should().BeFalse("one byte is still missing");

        reassembler.AddRecord(MakeFragment(HandshakeType.Certificate, 0, body, 999, 1), out _);
        reassembler.TryTakeNext(out var message).Should().BeTrue();
        message.Body.Should().Equal(body);
    }

    [Fact]
    public void Out_of_order_messages_are_buffered_until_their_turn()
    {
        var reassembler = new HandshakeReassembler();
        reassembler.Reset(0);

        var second = HandshakeMessage.Serialize(HandshakeType.ServerKeyExchange, 1, new byte[8]);
        var first = HandshakeMessage.Serialize(HandshakeType.ServerHello, 0, new byte[4]);

        reassembler.AddRecord(second, out _);
        reassembler.TryTakeNext(out _).Should().BeFalse("message_seq 0 has not arrived");

        reassembler.AddRecord(first, out _);
        reassembler.TryTakeNext(out var m0).Should().BeTrue();
        m0.Type.Should().Be(HandshakeType.ServerHello);
        reassembler.Consume(0);

        reassembler.TryTakeNext(out var m1).Should().BeTrue();
        m1.Type.Should().Be(HandshakeType.ServerKeyExchange);
    }

    [Fact]
    public void Already_consumed_messages_are_reported_as_retransmissions()
    {
        var reassembler = new HandshakeReassembler();
        reassembler.Reset(0);

        var hello = HandshakeMessage.Serialize(HandshakeType.ClientHello, 0, new byte[4]);
        reassembler.AddRecord(hello, out _);
        reassembler.TryTakeNext(out _).Should().BeTrue();
        reassembler.Consume(0);

        reassembler.AddRecord(hello, out var retransmission).Should().BeFalse();
        retransmission.Should().BeTrue();
    }

    [Fact]
    public void Several_messages_packed_into_one_record_are_all_parsed()
    {
        var reassembler = new HandshakeReassembler();
        reassembler.Reset(0);

        var a = HandshakeMessage.Serialize(HandshakeType.ServerHello, 0, new byte[4]);
        var b = HandshakeMessage.Serialize(HandshakeType.ServerHelloDone, 1, []);
        var record = new byte[a.Length + b.Length];
        a.CopyTo(record, 0);
        b.CopyTo(record, a.Length);

        reassembler.AddRecord(record, out _).Should().BeTrue();

        reassembler.TryTakeNext(out var first).Should().BeTrue();
        first.Type.Should().Be(HandshakeType.ServerHello);
        reassembler.Consume(0);
        reassembler.TryTakeNext(out var second).Should().BeTrue();
        second.Type.Should().Be(HandshakeType.ServerHelloDone);
        second.Body.Should().BeEmpty();
    }

    [Fact]
    public void A_fragment_outside_its_message_is_rejected()
    {
        var reassembler = new HandshakeReassembler();
        reassembler.Reset(0);

        var buffer = new byte[DtlsLimits.HandshakeHeaderLength + 10];
        var writer = new ByteWriter(buffer);
        writer.WriteU8((byte)HandshakeType.Certificate);
        writer.WriteU24(10);
        writer.WriteU16(0);
        writer.WriteU24(5); // offset
        writer.WriteU24(10); // length: runs past the end of the message
        writer.WriteBytes(new byte[10]);

        var act = () =>
        {
            var r = new HandshakeReassembler();
            r.AddRecord(buffer, out _);
        };

        act.Should().Throw<DtlsException>();
    }

    [Fact]
    public void An_absurdly_large_message_length_is_rejected()
    {
        var buffer = new byte[DtlsLimits.HandshakeHeaderLength];
        var writer = new ByteWriter(buffer);
        writer.WriteU8((byte)HandshakeType.Certificate);
        writer.WriteU24(0xFFFFFF);
        writer.WriteU16(0);
        writer.WriteU24(0);
        writer.WriteU24(0);

        var act = () =>
        {
            var r = new HandshakeReassembler();
            r.AddRecord(buffer, out _);
        };

        act.Should().Throw<DtlsException>()
            .Which.Alert.Should().Be(DtlsAlertDescription.DecodeError);
    }

    private static List<byte[]> Fragment(HandshakeType type, ushort messageSeq, byte[] body, int fragmentSize)
    {
        var fragments = new List<byte[]>();
        for (var offset = 0; offset < body.Length; offset += fragmentSize)
        {
            var count = Math.Min(fragmentSize, body.Length - offset);
            fragments.Add(MakeFragment(type, messageSeq, body, offset, count));
        }

        return fragments;
    }

    private static byte[] MakeFragment(HandshakeType type, ushort messageSeq, byte[] body, int offset, int count)
    {
        var buffer = new byte[DtlsLimits.HandshakeHeaderLength + count];
        var writer = new ByteWriter(buffer);
        writer.WriteU8((byte)type);
        writer.WriteU24((uint)body.Length);
        writer.WriteU16(messageSeq);
        writer.WriteU24((uint)offset);
        writer.WriteU24((uint)count);
        writer.WriteBytes(body.AsSpan(offset, count));
        return buffer;
    }
}
