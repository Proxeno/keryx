using System.Buffers.Binary;
using FluentAssertions;
using Keryx.Core;
using Keryx.Sctp;
using Xunit;

namespace Keryx.Sctp.Tests;

/// <summary>Wire-format round trips for the SCTP common header and every implemented chunk type.</summary>
public class SctpCodecTests
{
    private static SctpPacket RoundTrip(params SctpChunk[] chunks)
    {
        var packet = new SctpPacket(5000, 5000, 0xDEADBEEF);
        packet.Chunks.AddRange(chunks);
        var bytes = packet.ToArray();
        bytes.Length.Should().Be(packet.Length);
        return SctpPacket.Parse(bytes);
    }

    [Fact]
    public void CommonHeaderRoundTripsAndChecksumVerifies()
    {
        var packet = new SctpPacket(5000, 5000, 0x01020304);
        packet.Chunks.Add(new SctpCookieAckChunk());
        var bytes = packet.ToArray();

        bytes.Length.Should().Be(16);
        BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(0, 2)).Should().Be(5000);
        BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(2, 2)).Should().Be(5000);
        BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(4, 4)).Should().Be(0x01020304);

        // The checksum is stored little-endian, unlike every other header field.
        SctpPacket.ReadChecksum(bytes).Should().Be(SctpPacket.ComputeChecksum(bytes));
        BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(8, 4)).Should().Be(SctpPacket.ComputeChecksum(bytes));

        var parsed = SctpPacket.Parse(bytes);
        parsed.SourcePort.Should().Be(5000);
        parsed.VerificationTag.Should().Be(0x01020304);
        parsed.Chunks.Should().ContainSingle().Which.Should().BeOfType<SctpCookieAckChunk>();
    }

    [Fact]
    public void CorruptedPacketFailsChecksumVerification()
    {
        var packet = new SctpPacket(5000, 5000, 7);
        packet.Chunks.Add(new SctpCookieAckChunk());
        var bytes = packet.ToArray();
        bytes[7] ^= 0xFF;

        var act = () => SctpPacket.Parse(bytes);
        act.Should().Throw<ByteBufferException>().WithMessage("*checksum mismatch*");

        // The chunk layout is still intact, so parsing without verification succeeds.
        SctpPacket.Parse(bytes, verifyChecksum: false).Chunks.Should().HaveCount(1);
    }

    [Fact]
    public void DataChunkRoundTrips()
    {
        var payload = new byte[] { 1, 2, 3, 4, 5, 6, 7 };
        var chunk = new SctpDataChunk(0x11223344, 3, 9, SctpPpid.Binary, payload, beginning: true, ending: false, unordered: true);

        chunk.Length.Should().Be(4 + 12 + 7);
        chunk.PaddedLength.Should().Be(24);
        chunk.Flags.Should().Be(SctpDataChunk.BeginningFlag | SctpDataChunk.UnorderedFlag);

        var parsed = (SctpDataChunk)RoundTrip(chunk).Chunks[0];
        parsed.Tsn.Should().Be(0x11223344);
        parsed.StreamId.Should().Be(3);
        parsed.StreamSequence.Should().Be(9);
        parsed.PayloadProtocolId.Should().Be(SctpPpid.Binary);
        parsed.Payload.Should().Equal(payload);
        parsed.Beginning.Should().BeTrue();
        parsed.Ending.Should().BeFalse();
        parsed.Unordered.Should().BeTrue();
    }

    [Fact]
    public void IDataFirstFragmentCarriesPpidAndMid()
    {
        var payload = new byte[] { 10, 20, 30, 40, 50 };
        var chunk = new SctpIDataChunk(
            tsn: 0x0A0B0C0D,
            streamId: 7,
            messageIdentifier: 0x11223344,
            payloadProtocolId: SctpPpid.String,
            fragmentSequenceNumber: 0,
            payload: payload,
            beginning: true,
            ending: false,
            unordered: false);

        // 4-byte chunk header + 16-byte I-DATA header + 5-byte payload, padded to 28.
        chunk.Length.Should().Be(4 + 16 + 5);
        chunk.PaddedLength.Should().Be(28);
        chunk.Flags.Should().Be(SctpDataChunk.BeginningFlag);

        var parsed = (SctpIDataChunk)RoundTrip(chunk).Chunks[0];
        parsed.Type.Should().Be(SctpChunkType.IData);
        parsed.Tsn.Should().Be(0x0A0B0C0D);
        parsed.StreamId.Should().Be(7);
        parsed.MessageIdentifier.Should().Be(0x11223344);
        parsed.Beginning.Should().BeTrue();
        parsed.Ending.Should().BeFalse();

        // On the first fragment the fourth word is the PPID; the FSN is implicitly zero.
        parsed.PayloadProtocolId.Should().Be(SctpPpid.String);
        parsed.FragmentSequenceNumber.Should().Be(0);
        parsed.Payload.Should().Equal(payload);
    }

    [Fact]
    public void IDataContinuationFragmentCarriesFsn()
    {
        var payload = new byte[] { 99, 98, 97 };
        var chunk = new SctpIDataChunk(
            tsn: 500,
            streamId: 3,
            messageIdentifier: 42,
            payloadProtocolId: SctpPpid.Binary,
            fragmentSequenceNumber: 6,
            payload: payload,
            beginning: false,
            ending: true,
            unordered: true);

        chunk.Flags.Should().Be(SctpDataChunk.EndingFlag | SctpDataChunk.UnorderedFlag);

        var parsed = (SctpIDataChunk)RoundTrip(chunk).Chunks[0];
        parsed.MessageIdentifier.Should().Be(42);
        parsed.Beginning.Should().BeFalse();
        parsed.Ending.Should().BeTrue();
        parsed.Unordered.Should().BeTrue();

        // On a continuation fragment the fourth word is the FSN; no PPID is present on the wire.
        parsed.FragmentSequenceNumber.Should().Be(6);
        parsed.PayloadProtocolId.Should().Be(0);
        parsed.Payload.Should().Equal(payload);
    }

    [Fact]
    public void InitAdvertisesInterleavingInSupportedExtensions()
    {
        var init = new SctpInitChunk(SctpChunkType.Init) { InitiateTag = 1 };
        init.Parameters.Add(new SctpParameter(
            SctpParameterType.SupportedExtensions,
            new[] { (byte)SctpChunkType.ForwardTsn, (byte)SctpChunkType.ReConfig, (byte)SctpChunkType.IData }));

        var parsed = (SctpInitChunk)RoundTrip(init).Chunks[0];
        parsed.InterleavingSupported.Should().BeTrue();

        var withoutIData = new SctpInitChunk(SctpChunkType.Init) { InitiateTag = 1 };
        withoutIData.Parameters.Add(new SctpParameter(
            SctpParameterType.SupportedExtensions,
            new[] { (byte)SctpChunkType.ForwardTsn, (byte)SctpChunkType.ReConfig }));
        ((SctpInitChunk)RoundTrip(withoutIData).Chunks[0]).InterleavingSupported.Should().BeFalse();
    }

    [Fact]
    public void InitAndInitAckRoundTripWithParameters()
    {
        var init = new SctpInitChunk(SctpChunkType.Init)
        {
            InitiateTag = 0xAABBCCDD,
            AdvertisedReceiverWindow = 131072,
            NumberOfOutboundStreams = 1024,
            NumberOfInboundStreams = 1024,
            InitialTsn = 42,
        };
        init.Parameters.Add(new SctpParameter(SctpParameterType.ForwardTsnSupported, Array.Empty<byte>()));
        init.Parameters.Add(new SctpParameter(SctpParameterType.SupportedExtensions, new[] { (byte)SctpChunkType.ForwardTsn }));

        var parsed = (SctpInitChunk)RoundTrip(init).Chunks[0];
        parsed.Type.Should().Be(SctpChunkType.Init);
        parsed.InitiateTag.Should().Be(0xAABBCCDD);
        parsed.AdvertisedReceiverWindow.Should().Be(131072);
        parsed.NumberOfOutboundStreams.Should().Be(1024);
        parsed.NumberOfInboundStreams.Should().Be(1024);
        parsed.InitialTsn.Should().Be(42);
        parsed.Parameters.Should().HaveCount(2);
        parsed.ForwardTsnSupported.Should().BeTrue();
        parsed.FindParameter(SctpParameterType.ForwardTsnSupported)!.Type.Should().Be(0xC000);
        parsed.FindParameter(SctpParameterType.SupportedExtensions)!.Type.Should().Be(0x8008);

        var initAck = new SctpInitChunk(SctpChunkType.InitAck)
        {
            InitiateTag = 7,
            AdvertisedReceiverWindow = 1,
            NumberOfOutboundStreams = 2,
            NumberOfInboundStreams = 3,
            InitialTsn = 4,
        };
        var cookie = new byte[64];
        new Random(7).NextBytes(cookie);
        initAck.Parameters.Add(new SctpParameter(SctpParameterType.StateCookie, cookie));

        var parsedAck = (SctpInitChunk)RoundTrip(initAck).Chunks[0];
        parsedAck.Type.Should().Be(SctpChunkType.InitAck);
        parsedAck.StateCookie.Should().Equal(cookie);
        parsedAck.ForwardTsnSupported.Should().BeFalse();
    }

    [Fact]
    public void ParameterWithUnalignedLengthIsPadded()
    {
        var init = new SctpInitChunk(SctpChunkType.Init) { InitiateTag = 1 };
        init.Parameters.Add(new SctpParameter(0x9999, new byte[] { 0xAA }));
        init.Parameters.Add(new SctpParameter(0x8888, new byte[] { 0xBB, 0xCC }));

        // 5 bytes -> 8, 6 bytes -> 8.
        init.BodyLength.Should().Be(16 + 8 + 8);

        var parsed = (SctpInitChunk)RoundTrip(init).Chunks[0];
        parsed.Parameters.Should().HaveCount(2);
        parsed.Parameters[0].Value.Should().Equal(0xAA);
        parsed.Parameters[1].Value.Should().Equal(0xBB, 0xCC);
    }

    [Fact]
    public void SackRoundTripsWithGapsAndDuplicates()
    {
        var sack = new SctpSackChunk { CumulativeTsnAck = 1000, AdvertisedReceiverWindow = 65535 };
        sack.GapAckBlocks.Add(new SctpGapAckBlock(2, 4));
        sack.GapAckBlocks.Add(new SctpGapAckBlock(7, 7));
        sack.DuplicateTsns.Add(998);
        sack.DuplicateTsns.Add(999);

        sack.Length.Should().Be(4 + 12 + 8 + 8);

        var parsed = (SctpSackChunk)RoundTrip(sack).Chunks[0];
        parsed.CumulativeTsnAck.Should().Be(1000);
        parsed.AdvertisedReceiverWindow.Should().Be(65535);
        parsed.GapAckBlocks.Should().Equal(new SctpGapAckBlock(2, 4), new SctpGapAckBlock(7, 7));
        parsed.DuplicateTsns.Should().Equal(998u, 999u);
    }

    [Fact]
    public void HeartbeatRoundTripsAndEchoesInfo()
    {
        var info = new byte[] { 9, 8, 7, 6, 5, 4, 3, 2 };
        var parsed = (SctpHeartbeatChunk)RoundTrip(new SctpHeartbeatChunk(SctpChunkType.Heartbeat, info)).Chunks[0];
        parsed.Type.Should().Be(SctpChunkType.Heartbeat);
        parsed.Info.Should().Equal(info);

        var ack = (SctpHeartbeatChunk)RoundTrip(new SctpHeartbeatChunk(SctpChunkType.HeartbeatAck, info)).Chunks[0];
        ack.Type.Should().Be(SctpChunkType.HeartbeatAck);
        ack.Info.Should().Equal(info);
    }

    [Fact]
    public void AbortAndErrorRoundTripCauses()
    {
        var abort = new SctpAbortChunk { TagReflected = true };
        abort.Causes.Add(new SctpErrorCause(SctpErrorCauseCode.UserInitiatedAbort, "bye"u8.ToArray()));

        var parsedAbort = (SctpAbortChunk)RoundTrip(abort).Chunks[0];
        parsedAbort.TagReflected.Should().BeTrue();
        parsedAbort.Causes.Should().ContainSingle();
        parsedAbort.Causes[0].Code.Should().Be((ushort)SctpErrorCauseCode.UserInitiatedAbort);
        parsedAbort.Causes[0].Value.Should().Equal("bye"u8.ToArray());

        var error = new SctpErrorChunk();
        error.Causes.Add(new SctpErrorCause(SctpErrorCauseCode.InvalidStreamIdentifier, new byte[] { 0, 5, 0, 0 }));
        var parsedError = (SctpErrorChunk)RoundTrip(error).Chunks[0];
        parsedError.Causes[0].Code.Should().Be(1);
    }

    [Fact]
    public void ShutdownSequenceChunksRoundTrip()
    {
        var packet = RoundTrip(
            new SctpShutdownChunk(0x0BADF00D),
            new SctpShutdownAckChunk(),
            new SctpShutdownCompleteChunk { TagReflected = true });

        packet.Chunks.Should().HaveCount(3);
        ((SctpShutdownChunk)packet.Chunks[0]).CumulativeTsnAck.Should().Be(0x0BADF00D);
        packet.Chunks[1].Should().BeOfType<SctpShutdownAckChunk>();
        ((SctpShutdownCompleteChunk)packet.Chunks[2]).TagReflected.Should().BeTrue();
    }

    [Fact]
    public void CookieEchoAndAckRoundTrip()
    {
        var cookie = new byte[64];
        new Random(3).NextBytes(cookie);
        var packet = RoundTrip(new SctpCookieEchoChunk(cookie), new SctpCookieAckChunk());
        ((SctpCookieEchoChunk)packet.Chunks[0]).Cookie.Should().Equal(cookie);
        packet.Chunks[1].Should().BeOfType<SctpCookieAckChunk>();
    }

    [Fact]
    public void ForwardTsnRoundTripsWithStreamSkips()
    {
        var forward = new SctpForwardTsnChunk { NewCumulativeTsn = 4242 };
        forward.Streams.Add(new SctpForwardTsnStream(0, 11));
        forward.Streams.Add(new SctpForwardTsnStream(2, 3));

        forward.Type.Should().Be(SctpChunkType.ForwardTsn);
        ((byte)forward.Type).Should().Be(192);
        forward.Length.Should().Be(4 + 4 + 8);

        var parsed = (SctpForwardTsnChunk)RoundTrip(forward).Chunks[0];
        parsed.NewCumulativeTsn.Should().Be(4242);
        parsed.Streams.Should().Equal(new SctpForwardTsnStream(0, 11), new SctpForwardTsnStream(2, 3));
    }

    [Fact]
    public void ReConfigOutgoingResetRequestRoundTrips()
    {
        var request = new SctpOutgoingSsnResetRequest(
            requestSequence: 0x11223344,
            responseSequence: 0x55667788,
            sendersLastAssignedTsn: 0x99AABBCC,
            streams: new ushort[] { 0, 2, 4 });
        var chunk = new SctpReConfigChunk(request);

        ((byte)chunk.Type).Should().Be(130);

        // 12 fixed value bytes + 3 stream ids (2 bytes each) = 18 value; +4 param header = 22, padded
        // to 24; +4 chunk header = 28.
        chunk.Length.Should().Be(4 + 24);

        var parsed = (SctpReConfigChunk)RoundTrip(chunk).Chunks[0];
        parsed.Parameters.Should().ContainSingle();
        var outgoing = parsed.Parameters[0].Should().BeOfType<SctpOutgoingSsnResetRequest>().Subject;
        outgoing.RequestSequence.Should().Be(0x11223344);
        outgoing.ResponseSequence.Should().Be(0x55667788);
        outgoing.SendersLastAssignedTsn.Should().Be(0x99AABBCC);
        outgoing.Streams.Should().Equal((ushort)0, (ushort)2, (ushort)4);
    }

    [Fact]
    public void ReConfigIncomingResetRequestRoundTrips()
    {
        var chunk = new SctpReConfigChunk(new SctpIncomingSsnResetRequest(42, new ushort[] { 7 }));

        var parsed = (SctpReConfigChunk)RoundTrip(chunk).Chunks[0];
        var incoming = parsed.Parameters[0].Should().BeOfType<SctpIncomingSsnResetRequest>().Subject;
        incoming.RequestSequence.Should().Be(42);
        incoming.Streams.Should().Equal((ushort)7);
    }

    [Fact]
    public void ReConfigResponseRoundTripsWithAndWithoutTsnFields()
    {
        var response = new SctpReconfigResponse(0xABCDEF01, SctpReconfigResult.SuccessPerformed);
        var parsed = (SctpReConfigChunk)RoundTrip(new SctpReConfigChunk(response)).Chunks[0];
        var decoded = parsed.Parameters[0].Should().BeOfType<SctpReconfigResponse>().Subject;
        decoded.ResponseSequence.Should().Be(0xABCDEF01);
        decoded.Result.Should().Be(SctpReconfigResult.SuccessPerformed);
        decoded.HasTsnFields.Should().BeFalse();

        var withTsns = new SctpReconfigResponse(7, SctpReconfigResult.InProgress, sendersNextTsn: 100, receiversNextTsn: 200);
        var parsedTsns = (SctpReConfigChunk)RoundTrip(new SctpReConfigChunk(withTsns)).Chunks[0];
        var decodedTsns = parsedTsns.Parameters[0].Should().BeOfType<SctpReconfigResponse>().Subject;
        decodedTsns.HasTsnFields.Should().BeTrue();
        decodedTsns.Result.Should().Be(SctpReconfigResult.InProgress);
        decodedTsns.SendersNextTsn.Should().Be(100);
        decodedTsns.ReceiversNextTsn.Should().Be(200);
    }

    [Fact]
    public void ReConfigCarriesTwoParametersInOneChunk()
    {
        var chunk = new SctpReConfigChunk(
            new SctpOutgoingSsnResetRequest(1, 0, 500, new ushort[] { 3 }),
            new SctpReconfigResponse(9, SctpReconfigResult.SuccessPerformed));

        var parsed = (SctpReConfigChunk)RoundTrip(chunk).Chunks[0];
        parsed.Parameters.Should().HaveCount(2);
        parsed.Parameters[0].Should().BeOfType<SctpOutgoingSsnResetRequest>();
        parsed.Parameters[1].Should().BeOfType<SctpReconfigResponse>();
    }

    [Fact]
    public void UnknownChunkTypeSurvivesRoundTrip()
    {
        var unknown = new SctpUnknownChunk(0x7F, new byte[] { 1, 2, 3, 4 });
        var parsed = (SctpUnknownChunk)RoundTrip(unknown).Chunks[0];
        parsed.RawType.Should().Be(0x7F);
        parsed.Body.Should().Equal(1, 2, 3, 4);
    }

    [Fact]
    public void MultiChunkPacketPadsEveryChunkButTheLast()
    {
        var packet = new SctpPacket(5000, 5000, 0x1234);
        packet.Chunks.Add(new SctpDataChunk(1, 0, 0, SctpPpid.String, new byte[5]));
        packet.Chunks.Add(new SctpCookieAckChunk());

        // First chunk: length 21, padded to 24. Last chunk: 4 bytes, no padding emitted.
        packet.Chunks[0].Length.Should().Be(21);
        packet.Chunks[0].PaddedLength.Should().Be(24);
        packet.Length.Should().Be(12 + 24 + 4);

        var bytes = packet.ToArray();
        bytes.Length.Should().Be(40);
        bytes.AsSpan(12 + 21, 3).ToArray().Should().OnlyContain(b => b == 0);
        BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(12 + 2, 2)).Should().Be(21);

        var parsed = SctpPacket.Parse(bytes);
        parsed.Chunks.Should().HaveCount(2);
        ((SctpDataChunk)parsed.Chunks[0]).Payload.Should().HaveCount(5);
        parsed.Chunks[1].Should().BeOfType<SctpCookieAckChunk>();
    }

    [Fact]
    public void FinalChunkIsPaddedOnSendAndParsesWithOrWithoutTrailingPadding()
    {
        var packet = new SctpPacket(5000, 5000, 0x99);
        packet.Chunks.Add(new SctpDataChunk(1, 0, 0, SctpPpid.String, "hi"u8.ToArray()));

        // RFC 9260 §3.2: the sender MUST pad every chunk to a four-byte boundary, the final one
        // included — Chrome's dcsctp discards packets whose length is not a multiple of four.
        var withPadding = packet.ToArray();
        withPadding.Length.Should().Be(12 + 20);
        var parsed = SctpPacket.Parse(withPadding);
        parsed.Chunks.Should().ContainSingle();
        ((SctpDataChunk)parsed.Chunks[0]).Payload.Should().Equal("hi"u8.ToArray());

        // A robust receiver still accepts a peer that omitted the final padding.
        var withoutPadding = withPadding[..(12 + 18)];
        var checksum = SctpPacket.ComputeChecksum(withoutPadding);
        BinaryPrimitives.WriteUInt32LittleEndian(withoutPadding.AsSpan(8, 4), checksum);
        var lenient = SctpPacket.Parse(withoutPadding);
        lenient.Chunks.Should().ContainSingle();
        ((SctpDataChunk)lenient.Chunks[0]).Payload.Should().Equal("hi"u8.ToArray());
    }

    [Fact]
    public void TruncatedChunkLengthIsRejected()
    {
        var packet = new SctpPacket(5000, 5000, 1);
        packet.Chunks.Add(new SctpDataChunk(1, 0, 0, SctpPpid.String, new byte[8]));
        var bytes = packet.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(14, 2), 4096);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8, 4), SctpPacket.ComputeChecksum(bytes));

        var act = () => SctpPacket.Parse(bytes);
        act.Should().Throw<ByteBufferException>();
    }
}
