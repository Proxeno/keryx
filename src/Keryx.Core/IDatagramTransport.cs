namespace Keryx.Core;

/// <summary>Receives datagrams from an <see cref="IDatagramTransport"/>.</summary>
/// <param name="datagram">The received datagram. Valid only for the duration of the call; copy it to retain it.</param>
public delegate void DatagramReceivedHandler(ReadOnlySpan<byte> datagram);

/// <summary>
/// An unreliable, message-oriented, bidirectional transport: the seam between Keryx layers.
/// </summary>
/// <remarks>
/// ICE exposes its selected candidate pair as an <see cref="IDatagramTransport"/>; DTLS runs on
/// top of one and exposes another (its decrypted application-data stream) to SCTP. Implementations
/// may invoke <see cref="OnReceived"/> from arbitrary threads; consumers must be re-entrant-safe.
/// </remarks>
public interface IDatagramTransport
{
    /// <summary>Largest datagram, in bytes, that <see cref="Send"/> accepts without fragmenting.</summary>
    int MaxDatagramSize { get; }

    /// <summary>Raised once per received datagram.</summary>
    event DatagramReceivedHandler? OnReceived;

    /// <summary>Sends one datagram. Best-effort: delivery and ordering are not guaranteed.</summary>
    void Send(ReadOnlySpan<byte> datagram);
}
