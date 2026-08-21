using System.Security.Cryptography;
using FluentAssertions;
using Xunit;

namespace Keryx.Dtls.Tests;

public class RecordLayerTests
{
    [Fact]
    public void Record_header_round_trips()
    {
        var payload = Convert.FromHexString("DEADBEEFCAFE");
        var buffer = new byte[DtlsLimits.RecordHeaderLength + payload.Length];

        var written = DtlsRecordWriter.Write(
            buffer,
            ContentType.Handshake,
            ProtocolVersions.Dtls12,
            epoch: 3,
            sequenceNumber: 0x0000_1122_3344_5566UL & 0xFFFF_FFFF_FFFFUL,
            payload);

        written.Should().Be(buffer.Length);

        var reader = new DtlsRecordReader(buffer);
        reader.TryReadNext(out var record).Should().BeTrue();
        record.Type.Should().Be(ContentType.Handshake);
        record.Version.Should().Be(ProtocolVersions.Dtls12);
        record.Epoch.Should().Be(3);
        record.SequenceNumber.Should().Be(0x1122_3344_5566UL);
        record.Fragment.ToArray().Should().Equal(payload);
        reader.TryReadNext(out _).Should().BeFalse();
    }

    [Fact]
    public void Multiple_records_in_one_datagram_are_all_read()
    {
        var first = new byte[] { 1, 2, 3 };
        var second = new byte[] { 4, 5 };
        var third = Array.Empty<byte>();

        var datagram = new byte[(3 * DtlsLimits.RecordHeaderLength) + first.Length + second.Length];
        var offset = 0;
        offset += DtlsRecordWriter.Write(datagram.AsSpan(offset), ContentType.Handshake, ProtocolVersions.Dtls12, 0, 0, first);
        offset += DtlsRecordWriter.Write(datagram.AsSpan(offset), ContentType.Alert, ProtocolVersions.Dtls12, 0, 1, second);
        DtlsRecordWriter.Write(datagram.AsSpan(offset), ContentType.ApplicationData, ProtocolVersions.Dtls12, 1, 0, third);

        var reader = new DtlsRecordReader(datagram);
        var types = new List<ContentType>();
        while (reader.TryReadNext(out var record))
        {
            types.Add(record.Type);
        }

        types.Should().Equal(ContentType.Handshake, ContentType.Alert, ContentType.ApplicationData);
    }

    [Fact]
    public void Truncated_record_ends_the_datagram_without_throwing()
    {
        var payload = new byte[16];
        var datagram = new byte[DtlsLimits.RecordHeaderLength + payload.Length];
        DtlsRecordWriter.Write(datagram, ContentType.Handshake, ProtocolVersions.Dtls12, 0, 0, payload);

        var truncated = datagram[..(datagram.Length - 4)];
        var reader = new DtlsRecordReader(truncated);

        reader.TryReadNext(out _).Should().BeFalse();
    }

    [Fact]
    public void Aes_gcm_record_protection_round_trips_with_fixed_keys()
    {
        var key = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
        var salt = Convert.FromHexString("A0A1A2A3");
        using var sender = new AeadRecordCipher(key, salt);
        using var receiver = new AeadRecordCipher(key, salt);

        var plaintext = "the quick brown fox jumps over the lazy dog"u8.ToArray();
        var protectedBody = new byte[AeadRecordCipher.CiphertextLength(plaintext.Length)];

        var written = sender.Encrypt(
            ContentType.ApplicationData,
            ProtocolVersions.Dtls12,
            epoch: 1,
            sequenceNumber: 42,
            plaintext,
            protectedBody);

        written.Should().Be(protectedBody.Length);
        protectedBody.Should().HaveCount(plaintext.Length + AeadRecordCipher.Overhead);

        // The explicit nonce is epoch(2) || sequence(6), transmitted in the clear.
        protectedBody[..8].Should().Equal(Convert.FromHexString("000100000000002A"));

        var recovered = new byte[plaintext.Length];
        receiver.TryDecrypt(
            ContentType.ApplicationData,
            ProtocolVersions.Dtls12,
            1,
            42,
            protectedBody,
            recovered,
            out var length).Should().BeTrue();

        length.Should().Be(plaintext.Length);
        recovered.Should().Equal(plaintext);
    }

    [Theory]
    [InlineData("type")]
    [InlineData("epoch")]
    [InlineData("sequence")]
    [InlineData("ciphertext")]
    public void Aes_gcm_rejects_tampered_records(string what)
    {
        var key = new byte[16];
        var salt = new byte[4];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(salt);
        using var cipher = new AeadRecordCipher(key, salt);

        var plaintext = "keryx"u8.ToArray();
        var body = new byte[AeadRecordCipher.CiphertextLength(plaintext.Length)];
        cipher.Encrypt(ContentType.ApplicationData, ProtocolVersions.Dtls12, 1, 7, plaintext, body);

        var type = ContentType.ApplicationData;
        ushort epoch = 1;
        ulong sequence = 7;
        switch (what)
        {
            case "type":
                type = ContentType.Handshake;
                break;
            case "epoch":
                epoch = 2;
                break;
            case "sequence":
                sequence = 8;
                break;
            default:
                body[^1] ^= 0x01;
                break;
        }

        var recovered = new byte[plaintext.Length];
        cipher.TryDecrypt(type, ProtocolVersions.Dtls12, epoch, sequence, body, recovered, out _)
            .Should().BeFalse("a record whose AAD or ciphertext was altered must be discarded, not throw");
    }

    [Fact]
    public void Aes_gcm_rejects_a_body_shorter_than_the_overhead()
    {
        using var cipher = new AeadRecordCipher(new byte[16], new byte[4]);
        var recovered = new byte[64];

        cipher.TryDecrypt(ContentType.Alert, ProtocolVersions.Dtls12, 1, 0, new byte[8], recovered, out _)
            .Should().BeFalse();
    }

    [Fact]
    public void Key_block_partitioning_produces_interoperable_directions()
    {
        // A sanity check that the client's write cipher is the server's read cipher.
        var master = RandomNumberGenerator.GetBytes(48);
        var clientRandom = RandomNumberGenerator.GetBytes(32);
        var serverRandom = RandomNumberGenerator.GetBytes(32);
        var keyBlock = TlsPrf.KeyBlock(master, clientRandom, serverRandom, 40);

        using var clientWrite = new AeadRecordCipher(keyBlock.AsSpan(0, 16), keyBlock.AsSpan(32, 4));
        using var serverRead = new AeadRecordCipher(keyBlock.AsSpan(0, 16), keyBlock.AsSpan(32, 4));

        var plaintext = "direction check"u8.ToArray();
        var body = new byte[AeadRecordCipher.CiphertextLength(plaintext.Length)];
        clientWrite.Encrypt(ContentType.ApplicationData, ProtocolVersions.Dtls12, 1, 1, plaintext, body);

        var recovered = new byte[plaintext.Length];
        serverRead.TryDecrypt(ContentType.ApplicationData, ProtocolVersions.Dtls12, 1, 1, body, recovered, out var n)
            .Should().BeTrue();
        recovered[..n].Should().Equal(plaintext);
    }
}
