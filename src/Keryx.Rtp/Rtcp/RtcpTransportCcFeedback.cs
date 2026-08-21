using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Per-packet arrival status carried by transport-wide congestion control feedback
/// (<c>draft-holmer-rmcat-transport-wide-cc-extensions-01</c> §3.1.1).
/// </summary>
public enum TransportCcStatusSymbol : byte
{
    /// <summary>The packet did not arrive.</summary>
    NotReceived = 0,

    /// <summary>The packet arrived; its delta is an unsigned 8-bit value in 250 µs units.</summary>
    ReceivedSmallDelta = 1,

    /// <summary>The packet arrived; its delta is a signed 16-bit value in 250 µs units.</summary>
    ReceivedLargeOrNegativeDelta = 2,

    /// <summary>Reserved by the draft; treated as "arrived, no delta recorded".</summary>
    ReceivedWithoutTimestamp = 3,
}

/// <summary>The reported fate of one transport-wide sequence number.</summary>
public readonly struct TransportCcPacketStatus
{
    /// <summary>Creates a status entry.</summary>
    /// <param name="sequenceNumber">The transport-wide sequence number (RFC 8285 extension value).</param>
    /// <param name="symbol">The arrival status symbol.</param>
    /// <param name="deltaTicks">Arrival delta from the previous reported arrival, in 250 µs units.</param>
    /// <param name="arrivalTimeMicroseconds">Absolute arrival time reconstructed from the reference time.</param>
    public TransportCcPacketStatus(
        ushort sequenceNumber,
        TransportCcStatusSymbol symbol,
        int deltaTicks,
        long arrivalTimeMicroseconds)
    {
        SequenceNumber = sequenceNumber;
        Symbol = symbol;
        DeltaTicks = deltaTicks;
        ArrivalTimeMicroseconds = arrivalTimeMicroseconds;
    }

    /// <summary>The transport-wide sequence number this entry reports on.</summary>
    public ushort SequenceNumber { get; }

    /// <summary>The arrival status symbol.</summary>
    public TransportCcStatusSymbol Symbol { get; }

    /// <summary>Delta from the previously reported arrival, in 250 µs units; zero when not received.</summary>
    public int DeltaTicks { get; }

    /// <summary>
    /// Arrival time in microseconds on the receiver's clock, obtained by accumulating deltas onto the
    /// packet's reference time. Meaningless when <see cref="Received"/> is <see langword="false"/>.
    /// </summary>
    public long ArrivalTimeMicroseconds { get; }

    /// <summary>Whether the packet arrived at the remote endpoint.</summary>
    public bool Received => Symbol != TransportCcStatusSymbol.NotReceived;
}

/// <summary>
/// Transport-wide congestion control feedback (transport-cc),
/// <c>draft-holmer-rmcat-transport-wide-cc-extensions-01</c> §3.1: transport-layer feedback, FMT 15.
/// It reports the arrival time of every transport-wide sequence number in a window and is the input a
/// send-side bandwidth estimator runs on.
/// </summary>
/// <remarks>
/// Parsing is the priority path — these packets arrive several times a second and can describe
/// hundreds of sequence numbers. The parser makes exactly one list allocation for the statuses and
/// touches every input byte once. The builder is deliberately simple: it fills gaps with
/// "not received" and encodes runs of seven or more identical symbols as run-length chunks and
/// everything else as two-bit status-vector chunks.
/// </remarks>
public sealed class RtcpTransportCcFeedback : RtcpFeedbackPacket
{
    /// <summary>Length in bytes of the fixed part of the FCI, before the packet status chunks.</summary>
    public const int FixedFeedbackControlInformationLength = 8;

    /// <summary>Resolution of the receive-delta fields, in microseconds.</summary>
    public const int DeltaTickMicroseconds = 250;

    /// <summary>Resolution of the reference-time field, in microseconds.</summary>
    public const int ReferenceTimeTickMicroseconds = 64_000;

    /// <summary>Largest run a single run-length chunk can express.</summary>
    public const int MaxRunLength = (1 << 13) - 1;

    private readonly List<TransportCcPacketStatus> _statuses = [];
    private long _lastArrivalMicroseconds;
    private byte[]? _encoded;

    /// <summary>Creates an empty feedback packet.</summary>
    public RtcpTransportCcFeedback()
    {
    }

    /// <summary>The transport-wide sequence number the first status entry refers to.</summary>
    public ushort BaseSequenceNumber { get; set; }

    /// <summary>
    /// Reference time in units of 64 ms, a signed 24-bit value. Arrival times are reconstructed by
    /// accumulating the receive deltas onto it.
    /// </summary>
    public int ReferenceTime { get; set; }

    /// <summary>The reference time expressed in microseconds.</summary>
    public long ReferenceTimeMicroseconds => (long)ReferenceTime * ReferenceTimeTickMicroseconds;

    /// <summary>Counter incremented once per feedback packet, used to detect feedback loss.</summary>
    public byte FeedbackPacketCount { get; set; }

    /// <summary>The reported statuses, in ascending sequence-number order starting at <see cref="BaseSequenceNumber"/>.</summary>
    public IReadOnlyList<TransportCcPacketStatus> PacketStatuses => _statuses;

    /// <summary>Number of sequence numbers this packet reports on — the packet status count field.</summary>
    public int PacketStatusCount => _statuses.Count;

    /// <inheritdoc />
    public override RtcpPacketType PacketType => RtcpPacketType.TransportLayerFeedback;

    /// <inheritdoc />
    public override byte FeedbackMessageType => (byte)RtcpTransportFeedbackType.TransportCc;

    /// <inheritdoc />
    protected override int FeedbackControlInformationLength => Encode().Length;

    /// <summary>
    /// Records the arrival of one transport-wide sequence number. Sequence numbers must be added in
    /// ascending order; any gap is filled with <see cref="TransportCcStatusSymbol.NotReceived"/>
    /// entries. The first call fixes <see cref="BaseSequenceNumber"/> and <see cref="ReferenceTime"/>.
    /// </summary>
    /// <param name="sequenceNumber">The transport-wide sequence number that arrived.</param>
    /// <param name="arrivalTimeMicroseconds">Its arrival time on the receiver's clock, in microseconds.</param>
    /// <exception cref="InvalidOperationException">
    /// The arrival delta does not fit the 16-bit signed receive-delta field, so a new feedback packet
    /// must be started.
    /// </exception>
    public void AddPacket(ushort sequenceNumber, long arrivalTimeMicroseconds)
    {
        _encoded = null;

        if (_statuses.Count == 0)
        {
            BaseSequenceNumber = sequenceNumber;
            ReferenceTime = (int)Math.Floor(arrivalTimeMicroseconds / (double)ReferenceTimeTickMicroseconds);
            _lastArrivalMicroseconds = ReferenceTimeMicroseconds;
        }
        else
        {
            var expected = (ushort)(BaseSequenceNumber + _statuses.Count);
            while (expected != sequenceNumber)
            {
                _statuses.Add(new TransportCcPacketStatus(expected, TransportCcStatusSymbol.NotReceived, 0, 0));
                expected++;
            }
        }

        var deltaTicks = (long)Math.Round(
            (arrivalTimeMicroseconds - _lastArrivalMicroseconds) / (double)DeltaTickMicroseconds,
            MidpointRounding.AwayFromZero);

        if (deltaTicks is < short.MinValue or > short.MaxValue)
        {
            throw new InvalidOperationException(
                "The arrival delta does not fit the transport-cc receive-delta field; start a new feedback packet.");
        }

        _lastArrivalMicroseconds += deltaTicks * DeltaTickMicroseconds;
        var symbol = deltaTicks is >= 0 and <= 255
            ? TransportCcStatusSymbol.ReceivedSmallDelta
            : TransportCcStatusSymbol.ReceivedLargeOrNegativeDelta;

        _statuses.Add(new TransportCcPacketStatus(sequenceNumber, symbol, (int)deltaTicks, _lastArrivalMicroseconds));
    }

    /// <summary>Records that a transport-wide sequence number did not arrive.</summary>
    /// <param name="sequenceNumber">The missing sequence number.</param>
    /// <exception cref="InvalidOperationException">No packet has been added yet, so there is no base sequence number.</exception>
    public void AddMissingPacket(ushort sequenceNumber)
    {
        if (_statuses.Count == 0)
        {
            throw new InvalidOperationException(
                "A transport-cc feedback packet must begin with a received packet to establish the reference time.");
        }

        _encoded = null;
        var expected = (ushort)(BaseSequenceNumber + _statuses.Count);
        while (true)
        {
            _statuses.Add(new TransportCcPacketStatus(expected, TransportCcStatusSymbol.NotReceived, 0, 0));
            if (expected == sequenceNumber)
            {
                return;
            }

            expected++;
        }
    }

    /// <summary>Parses a transport-cc feedback packet.</summary>
    /// <param name="buffer">The complete packet, common header included.</param>
    /// <param name="packet">On success, the parsed packet with every status expanded.</param>
    /// <returns>
    /// <see langword="false"/> when the packet is not transport-cc feedback, is truncated, or the
    /// packet status chunks and receive deltas do not add up to the declared packet status count.
    /// </returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtcpTransportCcFeedback? packet)
    {
        packet = null;
        if (!TryReadFeedbackHeader(
                buffer,
                RtcpPacketType.TransportLayerFeedback,
                (byte)RtcpTransportFeedbackType.TransportCc,
                out var senderSsrc,
                out var mediaSsrc,
                out var fci)
            || fci.Length < FixedFeedbackControlInformationLength)
        {
            return false;
        }

        try
        {
            var reader = new ByteReader(fci);
            var baseSequenceNumber = reader.ReadU16();
            var statusCount = reader.ReadU16();
            var referenceTime = SignExtend24(reader.ReadU24());
            var feedbackPacketCount = reader.ReadU8();

            var symbols = statusCount == 0
                ? []
                : new TransportCcStatusSymbol[statusCount];

            var decoded = 0;
            while (decoded < statusCount)
            {
                var chunk = reader.ReadU16();
                if ((chunk & 0x8000) == 0)
                {
                    var symbol = (TransportCcStatusSymbol)((chunk >> 13) & 0x03);
                    var run = chunk & 0x1FFF;
                    for (var i = 0; i < run && decoded < statusCount; i++)
                    {
                        symbols[decoded++] = symbol;
                    }
                }
                else if ((chunk & 0x4000) == 0)
                {
                    for (var i = 0; i < 14 && decoded < statusCount; i++)
                    {
                        var bit = (chunk >> (13 - i)) & 0x01;
                        symbols[decoded++] = bit == 0
                            ? TransportCcStatusSymbol.NotReceived
                            : TransportCcStatusSymbol.ReceivedSmallDelta;
                    }
                }
                else
                {
                    for (var i = 0; i < 7 && decoded < statusCount; i++)
                    {
                        symbols[decoded++] = (TransportCcStatusSymbol)((chunk >> (12 - (i * 2))) & 0x03);
                    }
                }
            }

            var parsed = new RtcpTransportCcFeedback
            {
                SenderSsrc = senderSsrc,
                MediaSsrc = mediaSsrc,
                BaseSequenceNumber = baseSequenceNumber,
                ReferenceTime = referenceTime,
                FeedbackPacketCount = feedbackPacketCount,
            };

            var arrival = parsed.ReferenceTimeMicroseconds;
            for (var i = 0; i < statusCount; i++)
            {
                var symbol = symbols[i];
                var sequenceNumber = (ushort)(baseSequenceNumber + i);
                var deltaTicks = symbol switch
                {
                    TransportCcStatusSymbol.ReceivedSmallDelta => reader.ReadU8(),
                    TransportCcStatusSymbol.ReceivedLargeOrNegativeDelta => (short)reader.ReadU16(),
                    _ => 0,
                };

                if (symbol == TransportCcStatusSymbol.NotReceived)
                {
                    parsed._statuses.Add(
                        new TransportCcPacketStatus(sequenceNumber, symbol, 0, 0));
                    continue;
                }

                arrival += (long)deltaTicks * DeltaTickMicroseconds;
                parsed._statuses.Add(new TransportCcPacketStatus(sequenceNumber, symbol, deltaTicks, arrival));
            }

            parsed._lastArrivalMicroseconds = arrival;
            packet = parsed;
            return true;
        }
        catch (ByteBufferException)
        {
            packet = null;
            return false;
        }
    }

    /// <inheritdoc />
    protected override int WriteFeedbackControlInformation(Span<byte> destination)
    {
        var encoded = Encode();
        encoded.CopyTo(destination);
        return encoded.Length;
    }

    private static int SignExtend24(uint value) =>
        (value & 0x00800000) != 0 ? (int)(value | 0xFF000000) : (int)value;

    private byte[] Encode()
    {
        if (_encoded is not null)
        {
            return _encoded;
        }

        var chunks = new List<ushort>();
        var deltaBytes = 0;

        var index = 0;
        while (index < _statuses.Count)
        {
            var symbol = _statuses[index].Symbol;
            var run = 1;
            while (index + run < _statuses.Count && _statuses[index + run].Symbol == symbol && run < MaxRunLength)
            {
                run++;
            }

            if (run >= 7)
            {
                chunks.Add((ushort)(((int)symbol << 13) | run));
                index += run;
            }
            else
            {
                var count = Math.Min(7, _statuses.Count - index);
                var chunk = 0xC000;
                for (var i = 0; i < count; i++)
                {
                    chunk |= (int)_statuses[index + i].Symbol << (12 - (i * 2));
                }

                chunks.Add((ushort)chunk);
                index += count;
            }
        }

        foreach (var status in _statuses)
        {
            deltaBytes += status.Symbol switch
            {
                TransportCcStatusSymbol.ReceivedSmallDelta => 1,
                TransportCcStatusSymbol.ReceivedLargeOrNegativeDelta => 2,
                _ => 0,
            };
        }

        var unpadded = FixedFeedbackControlInformationLength + (chunks.Count * 2) + deltaBytes;
        var padding = (4 - (unpadded % 4)) % 4;
        var buffer = new byte[unpadded + padding];

        var writer = new ByteWriter(buffer);
        writer.WriteU16(BaseSequenceNumber);
        writer.WriteU16((ushort)_statuses.Count);
        writer.WriteU24((uint)ReferenceTime & 0x00FFFFFF);
        writer.WriteU8(FeedbackPacketCount);

        foreach (var chunk in chunks)
        {
            writer.WriteU16(chunk);
        }

        foreach (var status in _statuses)
        {
            switch (status.Symbol)
            {
                case TransportCcStatusSymbol.ReceivedSmallDelta:
                    writer.WriteU8((byte)status.DeltaTicks);
                    break;
                case TransportCcStatusSymbol.ReceivedLargeOrNegativeDelta:
                    writer.WriteU16((ushort)(short)status.DeltaTicks);
                    break;
                default:
                    break;
            }
        }

        writer.WriteZero(padding);
        _encoded = buffer;
        return buffer;
    }
}
