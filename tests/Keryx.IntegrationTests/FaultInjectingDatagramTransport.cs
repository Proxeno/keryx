using System.Buffers.Binary;
using System.Diagnostics;
using Keryx.Core;
using Keryx.Rtp;
using Keryx.Rtp.Rtcp;

namespace Keryx.IntegrationTests;

/// <summary>Decides whether one datagram is a candidate for fault injection.</summary>
/// <param name="datagram">The datagram, exactly as it would go on the wire.</param>
/// <returns><see langword="true"/> when the fault profile may act on it.</returns>
internal delegate bool DatagramSelector(ReadOnlySpan<byte> datagram);

/// <summary>What a <see cref="FaultInjectingDatagramTransport"/> did with one datagram.</summary>
internal enum DatagramFault
{
    /// <summary>Passed through untouched.</summary>
    Forwarded,

    /// <summary>Discarded by the uniform loss model.</summary>
    Dropped,

    /// <summary>Discarded as part of a loss burst.</summary>
    BurstDropped,

    /// <summary>Forwarded, and a second copy was forwarded with it.</summary>
    Duplicated,

    /// <summary>Held back to be released after later datagrams.</summary>
    Reordered,

    /// <summary>Forwarded after an extra delay.</summary>
    Delayed,
}

/// <summary>Observes every fault decision, for tests that need to know which packets were hit.</summary>
/// <param name="fault">The decision taken.</param>
/// <param name="datagram">The datagram the decision applied to.</param>
internal delegate void DatagramFaultObserver(DatagramFault fault, ReadOnlySpan<byte> datagram);

/// <summary>
/// Reads the fields of a protected media datagram that SRTP leaves in the clear.
/// </summary>
/// <remarks>
/// SRTP encrypts the payload and authenticates the header, but never encrypts it (RFC 3711 §3.1), so
/// a fault injector sitting below SRTP can still classify traffic by payload type, sequence number
/// and SSRC — which is what a real lossy link's per-flow behaviour would depend on too.
/// </remarks>
internal static class DatagramClassifier
{
    /// <summary>Lowest first-octet value of an SRTP or SRTCP datagram (RFC 7983 §7).</summary>
    internal const byte MediaFirstByteMin = 128;

    /// <summary>Highest first-octet value of an SRTP or SRTCP datagram (RFC 7983 §7).</summary>
    internal const byte MediaFirstByteMax = 191;

    /// <summary>
    /// True for SRTP media only: RFC 7983 §7 puts STUN at 0-3 and DTLS at 20-63, and RFC 5761 §4
    /// separates muxed RTCP from RTP by the second octet. Faulting anything but media would break the
    /// handshake or silence the feedback that drives repair, so this is the default selector.
    /// </summary>
    /// <param name="datagram">The datagram to classify.</param>
    /// <returns><see langword="true"/> when the datagram is SRTP media.</returns>
    internal static bool IsSrtpMedia(ReadOnlySpan<byte> datagram) =>
        datagram.Length >= RtpHeader.FixedLength
        && datagram[0] is >= MediaFirstByteMin and <= MediaFirstByteMax
        && !RtcpDemultiplexer.IsRtcp(datagram);

    /// <summary>Builds a selector matching SRTP media carried by one synchronisation source.</summary>
    /// <param name="ssrc">The SSRC to fault; every other flow passes through untouched.</param>
    /// <returns>The selector.</returns>
    internal static DatagramSelector ForSsrc(uint ssrc) =>
        datagram => IsSrtpMedia(datagram) && ReadSsrc(datagram) == ssrc;

    /// <summary>Builds a selector matching SRTP media carried by either of two sources.</summary>
    /// <param name="first">The first SSRC to fault.</param>
    /// <param name="second">The second SSRC to fault.</param>
    /// <returns>The selector.</returns>
    internal static DatagramSelector ForSsrcs(uint first, uint second) =>
        datagram => IsSrtpMedia(datagram)
            && (ReadSsrc(datagram) == first || ReadSsrc(datagram) == second);

    /// <summary>Reads the RTP sequence number at octets 2-3.</summary>
    /// <param name="datagram">An SRTP datagram.</param>
    /// <returns>The sequence number.</returns>
    internal static ushort ReadSequenceNumber(ReadOnlySpan<byte> datagram) =>
        BinaryPrimitives.ReadUInt16BigEndian(datagram[2..]);

    /// <summary>Reads the SSRC at octets 8-11.</summary>
    /// <param name="datagram">An SRTP datagram.</param>
    /// <returns>The synchronisation source.</returns>
    internal static uint ReadSsrc(ReadOnlySpan<byte> datagram) =>
        BinaryPrimitives.ReadUInt32BigEndian(datagram[8..]);

    /// <summary>Reads the seven-bit payload type from octet 1.</summary>
    /// <param name="datagram">An SRTP datagram.</param>
    /// <returns>The payload type.</returns>
    internal static byte ReadPayloadType(ReadOnlySpan<byte> datagram) => (byte)(datagram[1] & 0x7F);
}

/// <summary>
/// The impairments applied to one direction of a <see cref="FaultInjectingDatagramTransport"/>.
/// </summary>
/// <remarks>
/// Every impairment is independent and each one applies only to datagrams the
/// <see cref="Selector"/> accepts. A profile left at its defaults is a no-op.
/// </remarks>
internal sealed class FaultProfile
{
    /// <summary>Probability, 0 to 1, that a matching datagram is dropped outright.</summary>
    internal double DropProbability { get; set; }

    /// <summary>
    /// Trigger a loss burst every this many matching datagrams. Zero disables burst loss.
    /// </summary>
    internal int BurstEvery { get; set; }

    /// <summary>How many consecutive matching datagrams a triggered burst swallows.</summary>
    internal int BurstLength { get; set; }

    /// <summary>Probability, 0 to 1, that a matching datagram is delivered twice.</summary>
    internal double DuplicateProbability { get; set; }

    /// <summary>Probability, 0 to 1, that a matching datagram is held back and released later.</summary>
    internal double ReorderProbability { get; set; }

    /// <summary>How many later matching datagrams overtake a held one before it is released.</summary>
    internal int ReorderDistance { get; set; } = 3;

    /// <summary>Smallest extra delay applied to a matching datagram.</summary>
    internal TimeSpan MinDelay { get; set; }

    /// <summary>Largest extra delay applied to a matching datagram; equal to <see cref="MinDelay"/> for a fixed delay.</summary>
    internal TimeSpan MaxDelay { get; set; }

    /// <summary>
    /// Hard cap on datagrams waiting out a delay. Beyond it the injector forwards immediately and
    /// counts an overflow, so a delay profile can never grow an unbounded queue.
    /// </summary>
    internal int MaxDelayed { get; set; } = 1024;

    /// <summary>Which datagrams may be faulted. Defaults to <see cref="DatagramClassifier.IsSrtpMedia"/>.</summary>
    internal DatagramSelector? Selector { get; set; }

    /// <summary>Called for every decision this profile takes.</summary>
    internal DatagramFaultObserver? Observer { get; set; }

    /// <summary>True when the profile would leave every datagram alone.</summary>
    internal bool IsIdle =>
        DropProbability <= 0
        && (BurstEvery <= 0 || BurstLength <= 0)
        && DuplicateProbability <= 0
        && ReorderProbability <= 0
        && MaxDelay <= TimeSpan.Zero;
}

/// <summary>What one direction of a <see cref="FaultInjectingDatagramTransport"/> did.</summary>
/// <param name="Total">Datagrams offered, faulted or not.</param>
/// <param name="Matched">Datagrams the selector accepted.</param>
/// <param name="Dropped">Datagrams the uniform loss model discarded.</param>
/// <param name="BurstDropped">Datagrams a loss burst discarded.</param>
/// <param name="Duplicated">Datagrams delivered a second time.</param>
/// <param name="Reordered">Datagrams held back and released out of order.</param>
/// <param name="Delayed">Datagrams forwarded after an added delay.</param>
/// <param name="DelayQueueHighWater">Largest number of datagrams ever waiting out a delay at once.</param>
/// <param name="DelayQueueOverflows">Datagrams forwarded immediately because the delay queue was full.</param>
internal readonly record struct FaultCounters(
    long Total,
    long Matched,
    long Dropped,
    long BurstDropped,
    long Duplicated,
    long Reordered,
    long Delayed,
    int DelayQueueHighWater,
    long DelayQueueOverflows)
{
    /// <summary>Every datagram the injector discarded, however it decided to.</summary>
    internal long TotalDropped => Dropped + BurstDropped;
}

/// <summary>
/// A seeded, deterministic lossy-link model that wraps an <see cref="IDatagramTransport"/>.
/// </summary>
/// <remarks>
/// <para>
/// Installed through <see cref="PeerConnectionConfig.TransportInterceptor"/>, it sits below DTLS and
/// SRTP, so it models the network rather than the stack: it can drop, duplicate, reorder and delay
/// datagrams but cannot see or forge their contents. Send and receive directions are configured
/// separately by <see cref="FaultProfile"/>s.
/// </para>
/// <para>
/// Only what a profile's selector accepts is ever faulted, and the default selector accepts SRTP
/// media alone — STUN, DTLS and SRTCP always pass through, or ICE would never nominate a pair, the
/// handshake would never finish, and the NACKs that drive repair would never arrive.
/// </para>
/// <para>
/// Every decision is drawn from a seeded <see cref="Random"/> under the direction's lock, so a given
/// seed and a given datagram order always produce the same faults.
/// </para>
/// </remarks>
internal sealed class FaultInjectingDatagramTransport : IDatagramTransport, IDisposable
{
    private readonly IDatagramTransport _inner;
    private readonly FaultPipe _send;
    private readonly FaultPipe _receive;

    /// <summary>Wraps a transport.</summary>
    /// <param name="inner">The transport to send on and receive from.</param>
    /// <param name="send">Impairments applied to outbound datagrams; null leaves the direction clean.</param>
    /// <param name="receive">Impairments applied to inbound datagrams; null leaves the direction clean.</param>
    /// <param name="seed">Seed for the deterministic decision stream.</param>
    /// <exception cref="ArgumentNullException"><paramref name="inner"/> is null.</exception>
    internal FaultInjectingDatagramTransport(
        IDatagramTransport inner,
        FaultProfile? send = null,
        FaultProfile? receive = null,
        int seed = 20260820)
    {
        ArgumentNullException.ThrowIfNull(inner);
        _inner = inner;
        _send = new FaultPipe(send ?? new FaultProfile(), seed, d => _inner.Send(d));
        _receive = new FaultPipe(receive ?? new FaultProfile(), seed ^ 0x5EED, Deliver);
        _inner.OnReceived += OnInnerReceived;
    }

    /// <inheritdoc/>
    public event DatagramReceivedHandler? OnReceived;

    /// <inheritdoc/>
    public int MaxDatagramSize => _inner.MaxDatagramSize;

    /// <summary>Counters for the send direction.</summary>
    internal FaultCounters SendCounters => _send.Counters;

    /// <summary>Counters for the receive direction.</summary>
    internal FaultCounters ReceiveCounters => _receive.Counters;

    /// <inheritdoc/>
    public void Send(ReadOnlySpan<byte> datagram) => _send.Process(datagram);

    /// <summary>Releases every held and delayed datagram immediately, in both directions.</summary>
    internal void Flush()
    {
        _send.Flush();
        _receive.Flush();
    }

    /// <summary>Stops the delay pumps and unsubscribes from the wrapped transport.</summary>
    public void Dispose()
    {
        _inner.OnReceived -= OnInnerReceived;
        _send.Dispose();
        _receive.Dispose();
    }

    private void OnInnerReceived(ReadOnlySpan<byte> datagram) => _receive.Process(datagram);

    private void Deliver(ReadOnlySpan<byte> datagram) => OnReceived?.Invoke(datagram);

    /// <summary>One direction's impairment machinery.</summary>
    private sealed class FaultPipe : IDisposable
    {
        private readonly FaultProfile _profile;
        private readonly DatagramReceivedHandler _forward;
        private readonly DatagramSelector _selector;
        private readonly Random _random;
        private readonly object _gate = new();
        private readonly List<Delayed> _delayed = [];
        private readonly long _minDelayTicks;
        private readonly long _maxDelayTicks;

        private byte[]? _held;
        private int _heldLength;
        private int _heldCountdown;
        private int _burstRemaining;
        private long _total;
        private long _matched;
        private long _dropped;
        private long _burstDropped;
        private long _duplicated;
        private long _reordered;
        private long _delayedCount;
        private long _overflows;
        private int _highWater;
        private Thread? _pump;
        private bool _disposed;

        internal FaultPipe(FaultProfile profile, int seed, DatagramReceivedHandler forward)
        {
            _profile = profile;
            _forward = forward;
            _selector = profile.Selector ?? DatagramClassifier.IsSrtpMedia;
            _random = new Random(seed);
            _minDelayTicks = ToTicks(profile.MinDelay);
            _maxDelayTicks = ToTicks(profile.MaxDelay);
        }

        internal FaultCounters Counters
        {
            get
            {
                lock (_gate)
                {
                    return new FaultCounters(
                        _total,
                        _matched,
                        _dropped,
                        _burstDropped,
                        _duplicated,
                        _reordered,
                        _delayedCount,
                        _highWater,
                        _overflows);
                }
            }
        }

        internal void Process(ReadOnlySpan<byte> datagram)
        {
            lock (_gate)
            {
                _total++;
                if (_profile.IsIdle || !_selector(datagram))
                {
                    _forward(datagram);
                    return;
                }

                _matched++;

                if (_profile.BurstEvery > 0 && _profile.BurstLength > 0
                    && _burstRemaining == 0 && _matched % _profile.BurstEvery == 0)
                {
                    _burstRemaining = _profile.BurstLength;
                }

                if (_burstRemaining > 0)
                {
                    _burstRemaining--;
                    _burstDropped++;
                    _profile.Observer?.Invoke(DatagramFault.BurstDropped, datagram);
                    ReleaseHeldIfDue();
                    return;
                }

                if (_profile.DropProbability > 0 && _random.NextDouble() < _profile.DropProbability)
                {
                    _dropped++;
                    _profile.Observer?.Invoke(DatagramFault.Dropped, datagram);
                    ReleaseHeldIfDue();
                    return;
                }

                if (_profile.ReorderProbability > 0
                    && _held is null
                    && _profile.ReorderDistance > 0
                    && _random.NextDouble() < _profile.ReorderProbability)
                {
                    _held = datagram.ToArray();
                    _heldLength = datagram.Length;
                    _heldCountdown = _profile.ReorderDistance;
                    _reordered++;
                    _profile.Observer?.Invoke(DatagramFault.Reordered, datagram);
                    return;
                }

                var duplicate = _profile.DuplicateProbability > 0
                    && _random.NextDouble() < _profile.DuplicateProbability;

                Emit(datagram, duplicate ? DatagramFault.Duplicated : DatagramFault.Forwarded);
                if (duplicate)
                {
                    _duplicated++;
                    Emit(datagram, DatagramFault.Duplicated);
                }

                ReleaseHeldIfDue();
            }
        }

        internal void Flush()
        {
            lock (_gate)
            {
                ReleaseHeld();
                for (var i = 0; i < _delayed.Count; i++)
                {
                    Send(_delayed[i].Buffer.AsSpan(0, _delayed[i].Length));
                }

                _delayed.Clear();
                Monitor.PulseAll(_gate);
            }
        }

        public void Dispose()
        {
            Thread? pump;
            lock (_gate)
            {
                _disposed = true;
                _delayed.Clear();
                _held = null;
                pump = _pump;
                Monitor.PulseAll(_gate);
            }

            pump?.Join(TimeSpan.FromSeconds(2));
        }

        private static long ToTicks(TimeSpan value) =>
            value <= TimeSpan.Zero ? 0 : (long)(value.TotalSeconds * Stopwatch.Frequency);

        /// <summary>Forwards a datagram, applying the delay-jitter model.</summary>
        private void Emit(ReadOnlySpan<byte> datagram, DatagramFault fault, bool observe = true)
        {
            if (observe)
            {
                _profile.Observer?.Invoke(fault, datagram);
            }

            if (_maxDelayTicks <= 0)
            {
                Send(datagram);
                return;
            }

            if (_delayed.Count >= _profile.MaxDelayed)
            {
                _overflows++;
                Send(datagram);
                return;
            }

            var span = _maxDelayTicks - _minDelayTicks;
            var due = Stopwatch.GetTimestamp()
                + _minDelayTicks
                + (span > 0 ? (long)(_random.NextDouble() * span) : 0);
            _delayed.Add(new Delayed(due, datagram.ToArray(), datagram.Length));
            _delayedCount++;
            _highWater = Math.Max(_highWater, _delayed.Count);
            EnsurePump();
            Monitor.PulseAll(_gate);
        }

        private void ReleaseHeldIfDue()
        {
            if (_held is null)
            {
                return;
            }

            if (--_heldCountdown > 0)
            {
                return;
            }

            ReleaseHeld();
        }

        private void ReleaseHeld()
        {
            if (_held is null)
            {
                return;
            }

            var buffer = _held;
            var length = _heldLength;
            _held = null;

            // The observer already saw this datagram as Reordered when it was held back; reporting it
            // again on release would double-count it.
            Emit(buffer.AsSpan(0, length), DatagramFault.Forwarded, observe: false);
        }

        private void Send(ReadOnlySpan<byte> datagram)
        {
            try
            {
                _forward(datagram);
            }
            catch (InvalidOperationException)
            {
                // No nominated ICE pair yet, or the transport was disposed underneath us: the same
                // conditions the production send paths swallow.
            }
        }

        private void EnsurePump()
        {
            if (_pump is not null)
            {
                return;
            }

            _pump = new Thread(RunPump)
            {
                IsBackground = true,
                Name = "keryx-fault-delay",
            };
            _pump.Start();
        }

        private void RunPump()
        {
            lock (_gate)
            {
                while (!_disposed)
                {
                    if (_delayed.Count == 0)
                    {
                        Monitor.Wait(_gate, 20);
                        continue;
                    }

                    var now = Stopwatch.GetTimestamp();
                    var earliest = long.MaxValue;
                    for (var i = _delayed.Count - 1; i >= 0; i--)
                    {
                        var entry = _delayed[i];
                        if (entry.Due <= now)
                        {
                            _delayed.RemoveAt(i);
                            Send(entry.Buffer.AsSpan(0, entry.Length));
                        }
                        else
                        {
                            earliest = Math.Min(earliest, entry.Due);
                        }
                    }

                    if (_delayed.Count == 0)
                    {
                        continue;
                    }

                    var waitMs = (int)Math.Clamp(
                        (earliest - Stopwatch.GetTimestamp()) * 1000 / Stopwatch.Frequency,
                        1,
                        20);
                    Monitor.Wait(_gate, waitMs);
                }
            }
        }

        private readonly record struct Delayed(long Due, byte[] Buffer, int Length);
    }
}
