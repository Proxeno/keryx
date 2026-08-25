using System.Collections.Concurrent;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;

namespace Keryx;

/// <summary>
/// The SFU broadcast fan-out primitive: takes one ingest RTP packet and a set of N subscribers and
/// produces the N per-subscriber outbound datagrams — each rewritten onto the subscriber's SSRC/sequence
/// space and SRTP-encrypted under that subscriber's own keys — encrypting the N subscribers <b>in
/// parallel</b> across a worker pool sized to the machine's cores.
/// </summary>
/// <remarks>
/// <para>
/// Per-subscriber SRTP encrypt is the overwhelming majority of broadcast fan-out CPU and is
/// embarrassingly parallel: each subscriber owns a disjoint <see cref="RtpForwarder"/> and
/// <see cref="Srtp.SrtpEncryptContext"/> (see <see cref="BroadcastSubscriber"/>), so different
/// subscribers' rewrites and encrypts share no mutable state. This type exploits that by partitioning
/// the subscriber set into contiguous ranges — one range per worker — so each worker touches a disjoint
/// subset of subscribers and there is no shared-state contention and no lock on the hot path.
/// </para>
/// <para>
/// <b>Byte-identical to the serial path.</b> A parallel pass calls exactly the same
/// <see cref="RtpForwarder.TryForward"/> then <see cref="Srtp.SrtpEncryptContext.ProtectRtp"/> per
/// subscriber that <see cref="ForwardSerial"/> does; the only difference is which thread runs a given
/// subscriber. Because each subscriber's state is touched by one thread and shared with no other, the
/// produced bytes are identical to the serial fan-out for every subscriber, packet for packet.
/// <see cref="ForwardSerial"/> is retained as the reference (and as the small-N fast path).
/// </para>
/// <para>
/// <b>Ordering.</b> One pass offers exactly one packet to each subscriber, and a subscriber is touched
/// by exactly one worker per pass, so a single subscriber's stream is never processed in parallel with
/// itself. Call the fan-out once per ingest packet, in order; successive passes then preserve each
/// subscriber's sequence-number and SRTP-rollover ordering. Do not fan the same subscriber set out from
/// two threads at once.
/// </para>
/// <para>The ingest packet is read-only for the duration of a pass and every worker reads it concurrently;
/// do not mutate its backing memory until the pass returns.</para>
/// <para>This type is stateless across passes and its methods may be reused for every packet; it holds no
/// per-packet allocation.</para>
/// </remarks>
public sealed class BroadcastFanout
{
    // Below this subscriber count the fixed cost of dispatching onto worker threads outweighs the
    // encrypt work, so a pass runs inline on the calling thread. Chosen conservatively; the parallel
    // win only appears once there are enough subscribers to keep several cores busy.
    private const int DefaultParallelThreshold = 8;

    private readonly int _maxDegreeOfParallelism;
    private readonly int _parallelThreshold;

    /// <summary>Creates a fan-out that parallelises across up to <paramref name="maxDegreeOfParallelism"/> workers.</summary>
    /// <param name="maxDegreeOfParallelism">
    /// The most worker threads a single pass may use, or -1 (the default) for
    /// <see cref="Environment.ProcessorCount"/>. Clamped to at least 1.
    /// </param>
    /// <param name="parallelThreshold">
    /// The smallest subscriber count that runs in parallel; a pass with fewer subscribers runs serially
    /// on the calling thread. -1 (the default) selects a conservative built-in threshold.
    /// </param>
    public BroadcastFanout(int maxDegreeOfParallelism = -1, int parallelThreshold = -1)
    {
        _maxDegreeOfParallelism = maxDegreeOfParallelism <= 0
            ? Environment.ProcessorCount
            : maxDegreeOfParallelism;
        _parallelThreshold = parallelThreshold < 0 ? DefaultParallelThreshold : Math.Max(1, parallelThreshold);
    }

    /// <summary>The most worker threads a single parallel pass uses.</summary>
    public int MaxDegreeOfParallelism => _maxDegreeOfParallelism;

    /// <summary>
    /// Fans one ingest packet out to every subscriber in parallel, then appends the produced
    /// ready-to-send datagrams to <paramref name="datagrams"/> — the batch a datagram sender flushes in
    /// one call. <paramref name="datagrams"/> is cleared first. Datagram payloads are windows into the
    /// subscribers' output buffers and stay valid only until the next pass for those subscribers.
    /// </summary>
    /// <param name="classification">The ingest packet's layer classification.</param>
    /// <param name="ingestPacket">The complete ingest RTP packet (header and payload).</param>
    /// <param name="canStartLayer">True when the packet begins an independently decodable unit of its layer.</param>
    /// <param name="subscribers">The subscribers to fan the packet out to.</param>
    /// <param name="datagrams">Receives the produced datagrams; cleared before the pass appends to it.</param>
    /// <returns>The number of subscribers that forwarded (equal to the number of datagrams appended).</returns>
    public int Forward(
        in RtpLayerClassification classification,
        ReadOnlyMemory<byte> ingestPacket,
        bool canStartLayer,
        IReadOnlyList<BroadcastSubscriber> subscribers,
        List<BroadcastDatagram> datagrams)
    {
        ArgumentNullException.ThrowIfNull(datagrams);
        var forwarded = Forward(in classification, ingestPacket, canStartLayer, subscribers);

        datagrams.Clear();
        var count = subscribers.Count;
        for (var i = 0; i < count; i++)
        {
            if (subscribers[i].TryGetDatagram(out var datagram))
            {
                datagrams.Add(datagram);
            }
        }

        return forwarded;
    }

    /// <summary>
    /// Fans one ingest packet out to every subscriber in parallel, writing each subscriber's protected
    /// datagram into that subscriber's own output buffer. Read the results with
    /// <see cref="BroadcastSubscriber.TryGetDatagram"/> (or collect them with the
    /// <see cref="Forward(in RtpLayerClassification, ReadOnlyMemory{byte}, bool, IReadOnlyList{BroadcastSubscriber}, List{BroadcastDatagram})"/>
    /// overload). Never throws for a bad packet; a subscriber records a non-forward result instead.
    /// </summary>
    /// <param name="classification">The ingest packet's layer classification.</param>
    /// <param name="ingestPacket">The complete ingest RTP packet (header and payload).</param>
    /// <param name="canStartLayer">True when the packet begins an independently decodable unit of its layer.</param>
    /// <param name="subscribers">The subscribers to fan the packet out to.</param>
    /// <returns>The number of subscribers that forwarded the packet.</returns>
    public int Forward(
        in RtpLayerClassification classification,
        ReadOnlyMemory<byte> ingestPacket,
        bool canStartLayer,
        IReadOnlyList<BroadcastSubscriber> subscribers)
    {
        ArgumentNullException.ThrowIfNull(subscribers);

        var count = subscribers.Count;
        if (count == 0)
        {
            return 0;
        }

        if (count < _parallelThreshold || _maxDegreeOfParallelism == 1)
        {
            return ForwardSerial(in classification, ingestPacket.Span, canStartLayer, subscribers);
        }

        // Copy the by-ref/by-value inputs into locals the parallel body can capture (a ref-struct header
        // cannot cross threads, and an `in` parameter cannot be captured, so each worker re-parses the
        // header from the shared read-only ingest bytes on its own stack).
        var cls = classification;
        var packet = ingestPacket;
        var start = canStartLayer;
        var workers = Math.Min(_maxDegreeOfParallelism, count);

        var forwarded = 0;
        var options = new ParallelOptions { MaxDegreeOfParallelism = workers };

        // Even range partitioning: split the subscriber set into exactly `workers` contiguous [lo, hi)
        // blocks of near-equal size, one per worker. Each worker owns a disjoint block whose forwarders
        // and SRTP contexts it alone touches — no lock, no shared scratch — and the fixed block size
        // keeps the cores balanced instead of letting a load-balancing partitioner hand a few workers
        // most of the encrypts.
        var rangeSize = (count + workers - 1) / workers;
        var partitioner = Partitioner.Create(0, count, rangeSize);
        Parallel.ForEach(partitioner, options, range =>
        {
            var span = packet.Span;
            if (!RtpHeader.TryParse(span, out var header))
            {
                return;
            }

            var payload = span[header.HeaderLength..];
            var localForwarded = 0;
            for (var i = range.Item1; i < range.Item2; i++)
            {
                var subscriber = subscribers[i];
                subscriber.Process(in cls, in header, payload, start);
                if (subscriber.LastResult == RtpForwardResult.Forwarded)
                {
                    localForwarded++;
                }
            }

            // One interlocked add per worker range, not per subscriber: the only cross-thread write.
            if (localForwarded != 0)
            {
                Interlocked.Add(ref forwarded, localForwarded);
            }
        });

        return forwarded;
    }

    /// <summary>
    /// The serial reference fan-out: rewrites and encrypts the ingest packet for each subscriber in turn
    /// on the calling thread. Produces byte-identical output to <see cref="Forward(in RtpLayerClassification, ReadOnlyMemory{byte}, bool, IReadOnlyList{BroadcastSubscriber})"/>;
    /// used as the correctness reference and as the small-N fast path. Never throws for a bad packet.
    /// </summary>
    /// <param name="classification">The ingest packet's layer classification.</param>
    /// <param name="ingestPacket">The complete ingest RTP packet (header and payload).</param>
    /// <param name="canStartLayer">True when the packet begins an independently decodable unit of its layer.</param>
    /// <param name="subscribers">The subscribers to fan the packet out to.</param>
    /// <returns>The number of subscribers that forwarded the packet.</returns>
    public int ForwardSerial(
        in RtpLayerClassification classification,
        ReadOnlySpan<byte> ingestPacket,
        bool canStartLayer,
        IReadOnlyList<BroadcastSubscriber> subscribers)
    {
        ArgumentNullException.ThrowIfNull(subscribers);

        if (!RtpHeader.TryParse(ingestPacket, out var header))
        {
            return 0;
        }

        var payload = ingestPacket[header.HeaderLength..];
        var count = subscribers.Count;
        var forwarded = 0;
        for (var i = 0; i < count; i++)
        {
            var subscriber = subscribers[i];
            subscriber.Process(in classification, in header, payload, canStartLayer);
            if (subscriber.LastResult == RtpForwardResult.Forwarded)
            {
                forwarded++;
            }
        }

        return forwarded;
    }
}
