using System.Net;

namespace Keryx;

/// <summary>
/// One ready-to-send outbound datagram produced by a broadcast fan-out: the protected
/// (rewritten + SRTP-encrypted) packet bytes and the subscriber endpoint they are destined for.
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="BroadcastFanout"/> pass produces one of these per subscriber that forwarded the ingest
/// packet. The set of datagrams from a single pass is exactly the batch a datagram sender flushes in
/// one call (a <c>sendmmsg(2)</c>-style scatter send, the sibling batched-send work): payload plus
/// destination, nothing more.
/// </para>
/// <para>
/// <see cref="Payload"/> is a window into the owning <see cref="BroadcastSubscriber"/>'s reusable output
/// buffer, valid until that subscriber's next fan-out pass overwrites it. Send (or copy) the batch
/// before beginning the next pass for the same subscribers.
/// </para>
/// </remarks>
public readonly struct BroadcastDatagram
{
    /// <summary>Creates a datagram over a subscriber's protected packet bytes and its destination.</summary>
    /// <param name="payload">The protected (rewritten + SRTP-encrypted) packet, ready to place on the wire.</param>
    /// <param name="destination">The subscriber transport endpoint the datagram is sent to.</param>
    public BroadcastDatagram(ReadOnlyMemory<byte> payload, EndPoint destination)
    {
        Payload = payload;
        Destination = destination;
    }

    /// <summary>
    /// The protected packet bytes, ready for the wire. A window into the owning subscriber's output
    /// buffer, valid only until that subscriber's next fan-out pass overwrites it.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>The subscriber transport endpoint this datagram is destined for.</summary>
    public EndPoint Destination { get; }
}
