using System.Diagnostics;
using System.Globalization;
using FluentAssertions;
using Keryx.Rtp;
using Keryx.Sdp;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>One lossy-link experiment: what to impair, how much media to push, and how hard to repair.</summary>
internal sealed class LossScenario
{
    /// <summary>A short name for the printed report.</summary>
    internal required string Name { get; init; }

    /// <summary>Seed for the fault injector's decision stream; fixes the experiment exactly.</summary>
    internal int Seed { get; init; } = 20260820;

    /// <summary>Whether the sender offers and serves RFC 4588 retransmission.</summary>
    internal bool EnableRetransmission { get; init; } = true;

    /// <summary>Uniform loss probability applied to the video media stream, 0 to 1.</summary>
    internal double DropProbability { get; init; }

    /// <summary>Trigger a loss burst every this many video packets; zero disables burst loss.</summary>
    internal int BurstEvery { get; init; }

    /// <summary>How many consecutive video packets each burst swallows.</summary>
    internal int BurstLength { get; init; }

    /// <summary>Probability that a video packet is delivered twice.</summary>
    internal double DuplicateProbability { get; init; }

    /// <summary>Probability that a video packet is held back and released after later ones.</summary>
    internal double ReorderProbability { get; init; }

    /// <summary>How many packets overtake a reordered one.</summary>
    internal int ReorderDistance { get; init; } = 4;

    /// <summary>Smallest extra delay applied to a video packet.</summary>
    internal TimeSpan MinDelay { get; init; }

    /// <summary>Largest extra delay applied to a video packet.</summary>
    internal TimeSpan MaxDelay { get; init; }

    /// <summary>
    /// Also impair the RFC 4588 repair stream. Off by default: loss is modelled on the media SSRC,
    /// and the repair stream is a different source (RFC 4588 §4), so the two are independent flows.
    /// </summary>
    internal bool FaultRepairStream { get; init; }

    /// <summary>How many H.264 access units to send.</summary>
    internal int Frames { get; init; } = 600;

    /// <summary>Milliseconds between access units.</summary>
    internal int FramePaceMilliseconds { get; init; } = 4;

    /// <summary>How often the receiver re-scans for gaps and NACKs them.</summary>
    internal int NackIntervalMilliseconds { get; init; } = 60;

    /// <summary>
    /// How long the receiver keeps re-NACKing after the last frame was sent. A repair costs at least
    /// one round trip, and the sender's rate limit spaces repeated resends of the same packet, so the
    /// tail needs a settle window.
    /// </summary>
    internal int SettleMilliseconds { get; init; } = 2500;

    /// <summary>Optional per-second progress callback, used by the soak test.</summary>
    internal Action<LossProgress>? OnProgress { get; init; }
}

/// <summary>A point-in-time view of a running experiment, for long soaks.</summary>
/// <param name="Elapsed">How long the media pump has been running.</param>
/// <param name="PacketsSent">Video packets offered to the link so far.</param>
/// <param name="Dropped">Video packets the injector discarded so far.</param>
/// <param name="Arrived">Distinct media sequence numbers the receiver has seen.</param>
/// <param name="Recovered">Distinct sequence numbers recovered through RTX.</param>
/// <param name="Connected">Whether both peers are still connected.</param>
internal readonly record struct LossProgress(
    TimeSpan Elapsed,
    long PacketsSent,
    long Dropped,
    int Arrived,
    int Recovered,
    bool Connected);

/// <summary>What one lossy-link experiment measured.</summary>
internal sealed class LossReport
{
    /// <summary>The scenario that produced these numbers.</summary>
    internal required LossScenario Scenario { get; init; }

    /// <summary>Video packets the sender offered to the link.</summary>
    internal long PacketsOffered { get; init; }

    /// <summary>Video packets the injector discarded.</summary>
    internal long PacketsDropped { get; init; }

    /// <summary>Video packets the injector duplicated.</summary>
    internal long PacketsDuplicated { get; init; }

    /// <summary>Video packets the injector reordered.</summary>
    internal long PacketsReordered { get; init; }

    /// <summary>Most datagrams ever waiting out a delay in the injector at one time.</summary>
    internal int DelayQueueHighWater { get; init; }

    /// <summary>Datagrams the injector forwarded immediately because its delay queue was full.</summary>
    internal long DelayQueueOverflows { get; init; }

    /// <summary>The measured loss rate actually injected.</summary>
    internal double InjectedLossRate => PacketsOffered == 0 ? 0 : PacketsDropped / (double)PacketsOffered;

    /// <summary>Sequence numbers inside the detectable window: first arrival through last arrival.</summary>
    internal int WindowSize { get; init; }

    /// <summary>Sent packets before the receiver's first arrival; a receiver cannot NACK what it never saw.</summary>
    internal int UndetectableLeading { get; init; }

    /// <summary>Sent packets after the receiver's last arrival; the trailing gap is equally undetectable.</summary>
    internal int UndetectableTrailing { get; init; }

    /// <summary>Packets that arrived directly, inside the window.</summary>
    internal int ArrivedDirectly { get; init; }

    /// <summary>Packets that arrived only as an RFC 4588 repair, inside the window.</summary>
    internal int RecoveredByRtx { get; init; }

    /// <summary>Packets that never arrived at all, inside the window.</summary>
    internal int Holes { get; init; }

    /// <summary>Media sequence numbers the receiver saw more than once.</summary>
    internal int DuplicateArrivals { get; init; }

    /// <summary>Original sequence numbers repaired more than once.</summary>
    internal int DuplicateRepairs { get; init; }

    /// <summary>RTX packets whose payload failed to decapsulate (RFC 4588 §4).</summary>
    internal int MalformedRepairs { get; init; }

    /// <summary>The sender's retransmission counters at the end of the run.</summary>
    internal RetransmissionStats? Retransmission { get; init; }

    /// <summary>Video packets the sender's own counters say it transmitted.</summary>
    internal long SenderPacketsSent { get; init; }

    /// <summary>Inbound RTP packets the receiver decrypted and parsed, repairs included.</summary>
    internal long ReceiverRtpPackets { get; init; }

    /// <summary>
    /// Inbound media datagrams the receiver's SRTP layer refused. A datagram the link duplicated is
    /// a replay by RFC 3711 §3.3.2 and is refused here, before it can reach the media path at all.
    /// </summary>
    internal long ReceiverSrtpRejections { get; init; }

    /// <summary>Whether both peers were still connected when the run finished.</summary>
    internal bool StillConnected { get; init; }

    /// <summary>Managed heap size after the run, once collection has settled.</summary>
    internal long ManagedHeapBytes { get; init; }

    /// <summary>Fraction of the detectable window that arrived one way or the other.</summary>
    internal double Completeness =>
        WindowSize == 0 ? 0 : (ArrivedDirectly + RecoveredByRtx) / (double)WindowSize;

    /// <summary>Renders the report as a fixed-width block for the test log.</summary>
    /// <returns>The formatted report.</returns>
    internal string Format()
    {
        var culture = CultureInfo.InvariantCulture;
        var rtx = Retransmission;
        return string.Join(
            Environment.NewLine,
            $"--- {Scenario.Name} ---",
            $"  rtx negotiated      : {(rtx is null ? "no" : "yes")}",
            $"  video packets sent  : {PacketsOffered.ToString(culture)} (sender counted {SenderPacketsSent.ToString(culture)})",
            $"  injected drops      : {PacketsDropped.ToString(culture)} ({InjectedLossRate:P2})",
            $"  duplicated/reordered: {PacketsDuplicated.ToString(culture)} / {PacketsReordered.ToString(culture)}",
            $"  delay queue         : high water {DelayQueueHighWater.ToString(culture)}, {DelayQueueOverflows.ToString(culture)} overflow(s)",
            $"  detectable window   : {WindowSize.ToString(culture)} packets "
                + $"(+{UndetectableLeading.ToString(culture)} leading, +{UndetectableTrailing.ToString(culture)} trailing undetectable)",
            $"  arrived directly    : {ArrivedDirectly.ToString(culture)}",
            $"  recovered by RTX    : {RecoveredByRtx.ToString(culture)}",
            $"  holes               : {Holes.ToString(culture)}",
            $"  completeness        : {Completeness:P3}",
            $"  duplicate arrivals  : {DuplicateArrivals.ToString(culture)}; duplicate repairs: {DuplicateRepairs.ToString(culture)}; malformed repairs: {MalformedRepairs.ToString(culture)}",
            $"  receiver rtp/srtp   : {ReceiverRtpPackets.ToString(culture)} accepted, {ReceiverSrtpRejections.ToString(culture)} refused (replays included)",
            rtx is null
                ? "  retransmission      : disabled"
                : $"  retransmission      : nacks={rtx.Value.NacksReceived.ToString(culture)} requested={rtx.Value.NackRequestedPackets.ToString(culture)} "
                    + $"sent={rtx.Value.PacketsRetransmitted.ToString(culture)} bytes={rtx.Value.BytesRetransmitted.ToString(culture)} "
                    + $"misses={rtx.Value.HistoryMisses.ToString(culture)} suppressed={rtx.Value.Suppressed.ToString(culture)}",
            $"  connected at end    : {StillConnected}");
    }
}

/// <summary>
/// Runs one lossy-link experiment: a Keryx sender and a Keryx receiver on real UDP loopback with a
/// <see cref="FaultInjectingDatagramTransport"/> spliced under the sender's SRTP, a receiver that
/// detects gaps and drives RFC 4585 NACKs, and an RFC 4588 repair credit for every RTX packet that
/// decapsulates.
/// </summary>
/// <remarks>
/// <para>
/// Keryx's receive path is deliberately minimal — it does not generate NACKs of its own — so the
/// harness plays the receiver's loss detector: it tracks arriving media sequence numbers, re-scans
/// for gaps on a fixed cadence, and calls <see cref="PeerConnection.SendNack"/>, exactly as a browser
/// would. Repeated rounds are the point: RFC 4585 §3.1 expects a receiver to keep asking, and the
/// sender's per-packet resend rate limit means one round is not always enough.
/// </para>
/// <para>
/// Only the window between the first and last packet the receiver actually saw is scored. Loss
/// before the first arrival, or after the last, leaves no gap for any receiver to detect, so counting
/// it would measure the experiment's edges rather than the repair mechanism.
/// </para>
/// </remarks>
internal static class LossRecoveryHarness
{
    private const int MaxDatagram = 2048;

    /// <summary>Runs one experiment end to end.</summary>
    /// <param name="scenario">What to impair and how much media to push.</param>
    /// <param name="output">Where the report is written.</param>
    /// <param name="cancellationToken">Aborts the run.</param>
    /// <returns>The measured report.</returns>
    internal static async Task<LossReport> RunAsync(
        LossScenario scenario,
        ITestOutputHelper output,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scenario);
        ArgumentNullException.ThrowIfNull(output);

        // Ground truth, recorded below SRTP on the send path. SRTP leaves the RTP header in the clear
        // (RFC 3711 §3.1), so the injector can record exactly which sequence numbers it offered to the
        // link and which of them it swallowed.
        var offered = new SequenceSet();
        var dropped = new SequenceSet();

        var senderConfig = TestSupport.NewConfig();
        senderConfig.EnableRetransmission = scenario.EnableRetransmission;

        uint mediaSsrc = 0;
        uint repairSsrc = 0;
        FaultInjectingDatagramTransport? injector = null;

        var profile = new FaultProfile
        {
            DropProbability = scenario.DropProbability,
            BurstEvery = scenario.BurstEvery,
            BurstLength = scenario.BurstLength,
            DuplicateProbability = scenario.DuplicateProbability,
            ReorderProbability = scenario.ReorderProbability,
            ReorderDistance = scenario.ReorderDistance,
            MinDelay = scenario.MinDelay,
            MaxDelay = scenario.MaxDelay,
            Selector = datagram =>
            {
                if (!DatagramClassifier.IsSrtpMedia(datagram))
                {
                    return false;
                }

                var ssrc = DatagramClassifier.ReadSsrc(datagram);
                return ssrc == Volatile.Read(ref mediaSsrc)
                    || (scenario.FaultRepairStream && ssrc == Volatile.Read(ref repairSsrc));
            },
            Observer = (fault, datagram) =>
            {
                if (DatagramClassifier.ReadSsrc(datagram) != Volatile.Read(ref mediaSsrc))
                {
                    return;
                }

                var sequenceNumber = DatagramClassifier.ReadSequenceNumber(datagram);
                offered.Add(sequenceNumber);
                if (fault is DatagramFault.Dropped or DatagramFault.BurstDropped)
                {
                    dropped.Add(sequenceNumber);
                }
            },
        };

        senderConfig.TransportInterceptor = inner =>
            injector = new FaultInjectingDatagramTransport(inner, profile, seed: scenario.Seed);

        await using var sender = new PeerConnection(senderConfig);
        await using var receiver = new PeerConnection(TestSupport.NewConfig());

        Volatile.Write(ref mediaSsrc, sender.VideoSsrc);
        Volatile.Write(ref repairSsrc, sender.VideoRtxSsrc);

        var arrived = new SequenceSet();
        var recovered = new SequenceSet();
        var malformedRepairs = 0;
        var haveWindow = 0;
        ushort first = 0;
        var highest = 0;

        sender.OnLocalIceCandidate += (_, e) => receiver.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await sender.CreateOfferAsync(cancellationToken);
        await receiver.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await receiver.CreateAnswerAsync(cancellationToken);
        await sender.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        var rtxPayloadType = sender.NegotiatedVideoRtxPayloadType;
        var mediaPayloadType = MediaPayloadType(offer);

        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind != MediaKind.Video)
            {
                return;
            }

            if (rtxPayloadType is { } rtxPt && info.PayloadType == rtxPt)
            {
                // RFC 4588 §4: reconstruct the original packet from the repair, exactly as a receiver
                // must before handing it to the jitter buffer.
                Span<byte> rtxPacket = stackalloc byte[MaxDatagram];
                Span<byte> original = stackalloc byte[MaxDatagram];
                var header = new RtpHeader
                {
                    Version = RtpHeader.SupportedVersion,
                    Marker = info.Marker,
                    PayloadType = info.PayloadType,
                    SequenceNumber = info.SequenceNumber,
                    Timestamp = info.Timestamp,
                    Ssrc = info.Ssrc,
                };

                if (payload.Length + RtpHeader.FixedLength > MaxDatagram
                    || !header.TryWriteTo(rtxPacket, out var headerLength))
                {
                    Interlocked.Increment(ref malformedRepairs);
                    return;
                }

                payload.CopyTo(rtxPacket[headerLength..]);
                if (!RtxPacket.TryDecapsulate(
                        rtxPacket[..(headerLength + payload.Length)],
                        Volatile.Read(ref mediaSsrc),
                        mediaPayloadType,
                        original,
                        out var length,
                        out var originalSequenceNumber)
                    || !RtpPacket.TryParse(original[..length], out var reconstructed)
                    || reconstructed.Header.SequenceNumber != originalSequenceNumber
                    || reconstructed.Header.Ssrc != Volatile.Read(ref mediaSsrc)
                    || reconstructed.Header.PayloadType != mediaPayloadType)
                {
                    Interlocked.Increment(ref malformedRepairs);
                    return;
                }

                recovered.Add(originalSequenceNumber);
                return;
            }

            arrived.Add(info.SequenceNumber);

            if (Interlocked.CompareExchange(ref haveWindow, 1, 0) == 0)
            {
                first = info.SequenceNumber;
            }

            var distance = unchecked((ushort)(info.SequenceNumber - Volatile.Read(ref first)));
            if (distance < 32768 && distance > Volatile.Read(ref highest))
            {
                Volatile.Write(ref highest, distance);
            }
        };

        (await sender.WaitForConnectedAsync(TimeSpan.FromSeconds(20), cancellationToken)).Should().BeTrue();
        (await receiver.WaitForConnectedAsync(TimeSpan.FromSeconds(20), cancellationToken)).Should().BeTrue();

        if (scenario.EnableRetransmission)
        {
            rtxPayloadType.Should().NotBeNull("a Keryx answer keeps the RFC 4588 rtx codec");
        }
        else
        {
            rtxPayloadType.Should().BeNull("retransmission was switched off in the sender's config");
        }

        // ------------------------------------------------------------------ the receiver's loss detector
        using var nackLoop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var nackTask = Task.Run(
            async () =>
            {
                var missing = new List<ushort>(256);
                while (!nackLoop.IsCancellationRequested)
                {
                    try
                    {
                        await Task.Delay(scenario.NackIntervalMilliseconds, nackLoop.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }

                    if (Volatile.Read(ref haveWindow) == 0)
                    {
                        continue;
                    }

                    missing.Clear();
                    var start = Volatile.Read(ref first);
                    var top = Volatile.Read(ref highest);
                    for (var i = 0; i < top; i++)
                    {
                        var sequenceNumber = unchecked((ushort)(start + i));
                        if (!arrived.Contains(sequenceNumber) && !recovered.Contains(sequenceNumber))
                        {
                            missing.Add(sequenceNumber);
                            if (missing.Count == 256)
                            {
                                break;
                            }
                        }
                    }

                    if (missing.Count > 0)
                    {
                        receiver.SendNack(Volatile.Read(ref mediaSsrc), missing);
                    }
                }
            },
            CancellationToken.None);

        // ------------------------------------------------------------------ the media pump
        var accessUnits = H264TestStream.ReadAccessUnits(90);
        var started = Stopwatch.StartNew();
        var nextProgress = TimeSpan.FromSeconds(1);
        uint timestamp = 0;
        for (var i = 0; i < scenario.Frames && !cancellationToken.IsCancellationRequested; i++)
        {
            sender.SendVideoFrame(accessUnits[i % accessUnits.Count], timestamp);
            timestamp += 3000;
            await Task.Delay(scenario.FramePaceMilliseconds, cancellationToken).ConfigureAwait(false);

            if (scenario.OnProgress is { } progress && started.Elapsed >= nextProgress)
            {
                nextProgress = started.Elapsed + TimeSpan.FromSeconds(1);
                progress(new LossProgress(
                    started.Elapsed,
                    offered.Count,
                    dropped.Count,
                    arrived.Count,
                    recovered.Count,
                    sender.State == PeerConnectionState.Connected
                        && receiver.State == PeerConnectionState.Connected));
            }
        }

        // ------------------------------------------------------------------ settle: keep re-NACKing the tail
        bool NoGapsInWindow()
        {
            var start = Volatile.Read(ref first);
            var top = Volatile.Read(ref highest);
            for (var i = 0; i < top; i++)
            {
                var sequenceNumber = unchecked((ushort)(start + i));
                if (!arrived.Contains(sequenceNumber) && !recovered.Contains(sequenceNumber))
                {
                    return false;
                }
            }

            return true;
        }

        var settleDeadline = Environment.TickCount64 + scenario.SettleMilliseconds;
        await TestSupport.WaitForAsync(
            () => Environment.TickCount64 >= settleDeadline || NoGapsInWindow(),
            scenario.SettleMilliseconds).ConfigureAwait(false);

        await nackLoop.CancelAsync().ConfigureAwait(false);
        await nackTask.ConfigureAwait(false);
        injector?.Flush();

        // Flush() only hands a held-for-reorder or still-delayed datagram to the socket; it does not
        // wait for the receiver's callback to run. A packet that the injector was still sitting on at
        // the settle deadline (e.g. a reorder hold too close to the end of the stream to reach its
        // release countdown on its own) lands on the wire here, but its arrival on the receiver thread
        // can still be a beat behind this point. Scoring immediately below would then see a real,
        // in-flight packet as a hole — a race, not a loss — so give it the same bounded, early-exit
        // wait the settle loop above uses. This costs nothing when Flush() had nothing left to release.
        await TestSupport.WaitForAsync(NoGapsInWindow, 2_000).ConfigureAwait(false);

        // ------------------------------------------------------------------ score
        // The detectable window runs from the lowest packet the receiver saw to the highest. Anything
        // the link swallowed outside it leaves no gap between two arrivals, so no receiver — Keryx,
        // Chrome or otherwise — could ever have asked for it back. Distances are measured as signed
        // 16-bit offsets from the first arrival so that reordering, which can make a lower sequence
        // number arrive second, does not truncate the window.
        var anchor = Volatile.Read(ref first);
        var lowest = 0;
        var top = 0;
        foreach (var sequenceNumber in arrived)
        {
            var offset = Distance(sequenceNumber, anchor);
            lowest = Math.Min(lowest, offset);
            top = Math.Max(top, offset);
        }

        var windowSize = top - lowest + 1;
        var leading = 0;
        var trailing = 0;
        var holes = 0;
        var direct = 0;
        var repaired = 0;

        foreach (var sequenceNumber in offered)
        {
            var offset = Distance(sequenceNumber, anchor);
            if (offset < lowest)
            {
                leading++;
                continue;
            }

            if (offset > top)
            {
                trailing++;
                continue;
            }

            if (arrived.Contains(sequenceNumber))
            {
                direct++;
            }
            else if (recovered.Contains(sequenceNumber))
            {
                repaired++;
            }
            else
            {
                holes++;
            }
        }

        var senderStats = sender.GetStats();
        var receiverStats = receiver.GetStats();
        var counters = injector?.SendCounters ?? default;
        var report = new LossReport
        {
            Scenario = scenario,
            PacketsOffered = offered.Count,
            PacketsDropped = dropped.Count,
            PacketsDuplicated = counters.Duplicated,
            PacketsReordered = counters.Reordered,
            DelayQueueHighWater = counters.DelayQueueHighWater,
            DelayQueueOverflows = counters.DelayQueueOverflows,
            WindowSize = windowSize,
            UndetectableLeading = leading,
            UndetectableTrailing = trailing,
            ArrivedDirectly = direct,
            RecoveredByRtx = repaired,
            Holes = holes,
            DuplicateArrivals = arrived.Repeats,
            DuplicateRepairs = recovered.Repeats,
            MalformedRepairs = malformedRepairs,
            Retransmission = senderStats.Video?.Retransmission,
            SenderPacketsSent = senderStats.Video?.PacketsSent ?? 0,
            ReceiverRtpPackets = receiverStats.RtpPacketsReceived,
            ReceiverSrtpRejections = receiverStats.SrtpAuthenticationFailures,
            StillConnected = sender.State == PeerConnectionState.Connected
                && receiver.State == PeerConnectionState.Connected,
            ManagedHeapBytes = GC.GetTotalMemory(forceFullCollection: false),
        };

        // The harness's sequence accounting covers exactly one wrap of the 16-bit space; past that it
        // would alias rather than count, so fail loudly instead of reporting a wrong number.
        offered.Count.Should().BeLessThan(
            60_000,
            "the harness's sequence accounting is exact only inside one wrap of the RTP sequence space");

        output.WriteLine(report.Format());

        await sender.CloseAsync().ConfigureAwait(false);
        await receiver.CloseAsync().ConfigureAwait(false);
        injector?.Dispose();
        return report;
    }

    /// <summary>
    /// A fixed, allocation-free set over the 16-bit RTP sequence space, so a long soak's accounting
    /// cannot itself be mistaken for a leak.
    /// </summary>
    /// <remarks>
    /// The whole space is reserved up front — 256 kB — and never grows. That makes the set exact only
    /// for runs shorter than one wrap of the sequence space; <see cref="LossRecoveryHarness"/> checks
    /// that bound rather than silently aliasing.
    /// </remarks>
    private sealed class SequenceSet : IEnumerable<ushort>
    {
        private readonly int[] _seen = new int[65536];
        private int _count;
        private int _repeats;

        /// <summary>Distinct sequence numbers in the set.</summary>
        internal int Count => Volatile.Read(ref _count);

        /// <summary>How many times a sequence number already in the set was added again.</summary>
        internal int Repeats => Volatile.Read(ref _repeats);

        /// <summary>Adds a sequence number.</summary>
        /// <param name="sequenceNumber">The sequence number.</param>
        /// <returns>True when it was not already present.</returns>
        internal bool Add(ushort sequenceNumber)
        {
            if (Interlocked.Exchange(ref _seen[sequenceNumber], 1) != 0)
            {
                Interlocked.Increment(ref _repeats);
                return false;
            }

            Interlocked.Increment(ref _count);
            return true;
        }

        /// <summary>Tests membership.</summary>
        /// <param name="sequenceNumber">The sequence number.</param>
        /// <returns>True when present.</returns>
        internal bool Contains(ushort sequenceNumber) => Volatile.Read(ref _seen[sequenceNumber]) != 0;

        /// <inheritdoc/>
        public IEnumerator<ushort> GetEnumerator()
        {
            for (var i = 0; i < _seen.Length; i++)
            {
                if (Volatile.Read(ref _seen[i]) != 0)
                {
                    yield return (ushort)i;
                }
            }
        }

        /// <inheritdoc/>
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    /// <summary>The signed 16-bit distance from an anchor sequence number, per RFC 3550 §A.1 wrapping.</summary>
    /// <param name="sequenceNumber">The sequence number to place.</param>
    /// <param name="anchor">The anchor it is measured against.</param>
    /// <returns>A value in -32768..32767.</returns>
    private static int Distance(ushort sequenceNumber, ushort anchor) =>
        unchecked((short)(sequenceNumber - anchor));

    /// <summary>Reads the primary video payload type out of the offer the sender built.</summary>
    private static byte MediaPayloadType(string offerSdp)
    {
        var offer = SessionDescription.Parse(offerSdp);
        foreach (var media in offer.MediaDescriptions)
        {
            if (!string.Equals(media.Media, "video", StringComparison.Ordinal))
            {
                continue;
            }

            foreach (var payloadType in media.GetPayloadTypes())
            {
                var rtpMap = media.GetRtpMap(payloadType);
                if (rtpMap is not null
                    && !string.Equals(rtpMap.EncodingName, "rtx", StringComparison.OrdinalIgnoreCase))
                {
                    return (byte)payloadType;
                }
            }
        }

        throw new InvalidOperationException("The offer carries no video codec.");
    }
}
