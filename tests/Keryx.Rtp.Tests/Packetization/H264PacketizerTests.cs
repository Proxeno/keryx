using FluentAssertions;
using Keryx.Rtp.Packetization;
using Xunit;

namespace Keryx.Rtp.Tests.Packetization;

/// <summary>
/// Golden-vector coverage for the RFC 6184 packetization-mode=1 packetizer and its depacketizer.
/// </summary>
public class H264PacketizerTests
{
    private const int MaxPayloadSize = 1200;

    private static readonly byte[] Sps = [0x67, 0x42, 0x00, 0x1E];
    private static readonly byte[] Pps = [0x68, 0xCE, 0x38, 0x80];
    private static readonly byte[] Idr = [0x65, 0x88, 0x84];

    private static byte[] AnnexBAccessUnit(params byte[][] nals)
    {
        var stream = new List<byte>();
        foreach (var nal in nals)
        {
            stream.AddRange([0x00, 0x00, 0x00, 0x01]);
            stream.AddRange(nal);
        }

        return [.. stream];
    }

    private static byte[] SyntheticNal(byte header, int length)
    {
        var nal = new byte[length];
        nal[0] = header;
        for (var i = 1; i < length; i++)
        {
            nal[i] = (byte)(i * 7 % 251);
        }

        return nal;
    }

    private static IReadOnlyList<RtpPayload> Packetize(byte[] accessUnit, int maxPayloadSize = MaxPayloadSize)
    {
        var writer = new CollectingRtpPayloadWriter();
        var packetizer = new H264Packetizer();
        // H.264 ignores the RTP timestamp; its marker is keyed off end-of-access-unit.
        var count = packetizer.Packetize(accessUnit, 0, maxPayloadSize, writer);
        count.Should().Be(writer.Payloads.Count);
        return writer.Payloads;
    }

    [Fact]
    public void Clock_rate_is_ninety_kilohertz()
    {
        // RFC 6184 §8.1: the RTP timestamp clock frequency for H.264 is 90 kHz.
        new H264Packetizer().ClockRate.Should().Be(90_000);
        new H264Packetizer().GetTimestampIncrement(AnnexBAccessUnit(Idr)).Should().Be(0);
    }

    [Fact]
    public void A_single_small_nal_becomes_a_single_nal_unit_packet()
    {
        // RFC 6184 §5.6: a single NAL unit packet carries the NAL unit verbatim, header included.
        var payloads = Packetize(AnnexBAccessUnit(Idr));

        payloads.Should().ContainSingle();
        payloads[0].Data.Should().Equal(Idr);
        payloads[0].Marker.Should().BeTrue();
    }

    [Fact]
    public void Small_nals_aggregate_into_a_byte_exact_stap_a()
    {
        // RFC 6184 §5.7.1: STAP-A is one aggregation header followed by, per NAL, a 16-bit size and
        // the NAL unit itself. The aggregation header's NRI is the maximum of the aggregated NRIs.
        var payloads = Packetize(AnnexBAccessUnit(Sps, Pps, Idr));

        payloads.Should().ContainSingle();
        payloads[0].Data.Should().Equal(
            0x78,                               // F=0, NRI=3, Type=24 (STAP-A)
            0x00, 0x04, 0x67, 0x42, 0x00, 0x1E, // SPS with its 16-bit size
            0x00, 0x04, 0x68, 0xCE, 0x38, 0x80, // PPS
            0x00, 0x03, 0x65, 0x88, 0x84);      // IDR slice
        payloads[0].Marker.Should().BeTrue();
    }

    [Fact]
    public void Stap_a_header_propagates_the_forbidden_bit_and_the_highest_nri()
    {
        // RFC 6184 §5.7.1: "The value of NRI MUST be the maximum of all the NAL units carried"; F is
        // the bitwise OR of the aggregated F bits.
        var low = new byte[] { 0x01, 0xAA };   // F=0, NRI=0
        var high = new byte[] { 0xA5, 0xBB };  // F=1, NRI=1

        var payloads = Packetize(AnnexBAccessUnit(low, high));
        payloads[0].Data[0].Should().Be(0xB8); // F=1, NRI=1, Type=24
    }

    [Fact]
    public void A_nal_that_fits_but_leaves_no_room_for_a_size_field_is_sent_on_its_own()
    {
        // A 10-byte NAL fits a 10-byte payload but a STAP-A carrying it would need 13 bytes.
        var nal = SyntheticNal(0x41, 10);
        var payloads = Packetize(AnnexBAccessUnit(nal), maxPayloadSize: 10);

        payloads.Should().ContainSingle();
        payloads[0].Data.Should().Equal(nal);
    }

    [Fact]
    public void Aggregation_stops_at_the_max_payload_size()
    {
        // Two 8-byte NALs need 1 + 2 + 8 + 2 + 8 = 21 bytes as one STAP-A; a 15-byte limit forces two
        // packets, and a single-NAL aggregate degrades to a single NAL unit packet.
        var first = SyntheticNal(0x41, 8);
        var second = SyntheticNal(0x41, 8);

        var payloads = Packetize(AnnexBAccessUnit(first, second), maxPayloadSize: 15);

        payloads.Should().HaveCount(2);
        payloads[0].Data.Should().Equal(first);
        payloads[0].Marker.Should().BeFalse();
        payloads[1].Data.Should().Equal(second);
        payloads[1].Marker.Should().BeTrue();
    }

    [Fact]
    public void A_large_nal_is_fragmented_into_fu_a_packets_with_correct_start_end_and_type_bits()
    {
        // RFC 6184 §5.8: FU indicator is F|NRI|28; the FU header is S|E|R|Type with R always zero,
        // and the original NAL header octet is not repeated in the fragment payloads.
        var nal = SyntheticNal(0x65, 5000);
        var payloads = Packetize(AnnexBAccessUnit(nal));

        var body = nal.Length - 1;                       // 4999 payload octets
        var perFragment = MaxPayloadSize - 2;            // 1198
        var expected = (body + perFragment - 1) / perFragment;
        payloads.Should().HaveCount(expected).And.HaveCount(5);

        for (var i = 0; i < payloads.Count; i++)
        {
            payloads[i].Data[0].Should().Be(0x7C);       // F=0, NRI=3, Type=28 (FU-A)
            var fuHeader = payloads[i].Data[1];
            (fuHeader & 0x1F).Should().Be(5);            // original NAL type: IDR slice
            (fuHeader & 0x20).Should().Be(0);            // R bit MUST be 0
            ((fuHeader & 0x80) != 0).Should().Be(i == 0);
            ((fuHeader & 0x40) != 0).Should().Be(i == payloads.Count - 1);
            payloads[i].Marker.Should().Be(i == payloads.Count - 1);
        }

        payloads.Take(payloads.Count - 1).Should().OnlyContain(p => p.Data.Length == MaxPayloadSize);
        payloads[^1].Data.Length.Should().Be(2 + (body % perFragment));
    }

    [Fact]
    public void Fragments_concatenate_back_to_the_original_nal_body()
    {
        var nal = SyntheticNal(0x65, 5000);
        var payloads = Packetize(AnnexBAccessUnit(nal));

        var reassembled = new List<byte> { nal[0] };
        foreach (var payload in payloads)
        {
            reassembled.AddRange(payload.Data.Skip(2));
        }

        reassembled.Should().Equal(nal);
    }

    [Fact]
    public void Marker_is_set_only_on_the_last_packet_of_the_access_unit()
    {
        // RFC 6184 §5.1: "the marker bit ... set to one for the last packet of the access unit".
        var payloads = Packetize(AnnexBAccessUnit(Sps, Pps, SyntheticNal(0x65, 5000)));

        payloads.Should().HaveCount(6); // one STAP-A for SPS+PPS, then five FU-A fragments
        payloads.Take(5).Should().OnlyContain(p => !p.Marker);
        payloads[^1].Marker.Should().BeTrue();
        payloads[0].Data[0].Should().Be(0x78); // STAP-A
        payloads[1].Data[0].Should().Be(0x7C); // FU-A
    }

    [Fact]
    public void An_empty_access_unit_produces_no_packets()
    {
        Packetize([]).Should().BeEmpty();
        Packetize([0x00, 0x00, 0x00, 0x01]).Should().BeEmpty();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(1199)]
    [InlineData(1200)]
    [InlineData(1201)]
    [InlineData(5000)]
    [InlineData(20000)]
    public void Depacketizer_reconstructs_the_access_unit_byte_for_byte(int idrLength)
    {
        var idr = SyntheticNal(0x65, idrLength);
        var accessUnit = AnnexBAccessUnit(Sps, Pps, idr);

        var payloads = Packetize(accessUnit);
        var depacketizer = new H264Depacketizer();

        byte[]? reconstructed = null;
        for (var i = 0; i < payloads.Count; i++)
        {
            if (depacketizer.TryAddPayload(payloads[i].Data, payloads[i].Marker, out var unit))
            {
                reconstructed = unit.ToArray();
            }
        }

        reconstructed.Should().NotBeNull();
        reconstructed.Should().Equal(accessUnit);
    }

    [Fact]
    public void Depacketizer_handles_consecutive_access_units()
    {
        var first = AnnexBAccessUnit(Sps, Pps, SyntheticNal(0x65, 3000));
        var second = AnnexBAccessUnit(SyntheticNal(0x41, 900));
        var depacketizer = new H264Depacketizer();

        foreach (var accessUnit in new[] { first, second })
        {
            byte[]? reconstructed = null;
            foreach (var payload in Packetize(accessUnit))
            {
                if (depacketizer.TryAddPayload(payload.Data, payload.Marker, out var unit))
                {
                    reconstructed = unit.ToArray();
                }
            }

            reconstructed.Should().Equal(accessUnit);
            depacketizer.BeginNextAccessUnit();
        }
    }

    [Fact]
    public void Depacketizer_rejects_a_stap_a_whose_size_field_runs_past_the_payload()
    {
        var depacketizer = new H264Depacketizer();
        depacketizer.TryAddPayload([0x78, 0x00, 0x40, 0x65, 0x01], marker: true, out _).Should().BeFalse();
    }

    [Fact]
    public void Depacketizer_rejects_a_fu_a_continuation_without_a_start_fragment()
    {
        var depacketizer = new H264Depacketizer();
        depacketizer.TryAddPayload([0x7C, 0x05, 0xAA], marker: false, out _).Should().BeFalse();
    }

    [Fact]
    public void Depacketizer_rejects_unsupported_aggregation_types()
    {
        var depacketizer = new H264Depacketizer();
        depacketizer.TryAddPayload([0x79, 0x00], marker: true, out _).Should().BeFalse(); // STAP-B
        depacketizer.TryAddPayload([0x7D, 0x00], marker: true, out _).Should().BeFalse(); // FU-B
    }

    [Fact]
    public void Packetizer_rejects_a_max_payload_size_too_small_for_a_fu_a_header()
    {
        var packetizer = new H264Packetizer();
        var writer = new CollectingRtpPayloadWriter();
        var accessUnit = AnnexBAccessUnit(Idr);
        var act = () => packetizer.Packetize(accessUnit, 0, 2, writer);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }
}
