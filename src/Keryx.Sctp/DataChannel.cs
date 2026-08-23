using System.Text;

namespace Keryx.Sctp;

/// <summary>Receives a complete user message from a <see cref="DataChannel"/>.</summary>
/// <param name="isBinary">True for binary payloads (PPID 53/57), false for UTF-8 strings (PPID 51/56).</param>
/// <param name="payload">
/// The reassembled message. Valid only for the duration of the call; copy it to retain it.
/// </param>
public delegate void DataChannelMessageHandler(bool isBinary, ReadOnlySpan<byte> payload);

/// <summary>
/// A WebRTC data channel (RFC 8831) carried on one bidirectional SCTP stream and negotiated in
/// band with DCEP (RFC 8832).
/// </summary>
/// <remarks>
/// Events are raised on whichever thread drives the association — the transport's receive thread
/// or the association's timer thread — never on the caller's thread. Handlers must be quick and
/// must not block; they may safely call back into <see cref="Send"/> and <see cref="SendText"/>.
/// </remarks>
public sealed class DataChannel
{
    private readonly SctpAssociation _association;
    private long _bufferedAmount;

    internal DataChannel(
        SctpAssociation association,
        int streamId,
        string label,
        string protocol,
        bool ordered,
        ushort? maxRetransmits,
        bool negotiatedByPeer)
    {
        _association = association;
        StreamId = streamId;
        Label = label;
        Protocol = protocol;
        Ordered = ordered;
        MaxRetransmits = maxRetransmits;
        NegotiatedByPeer = negotiatedByPeer;
        State = DataChannelState.Connecting;
    }

    /// <summary>Raised once the DCEP handshake completes and the channel becomes usable.</summary>
    public event Action? OnOpen;

    /// <summary>Raised for each complete user message received on this channel.</summary>
    public event DataChannelMessageHandler? OnMessage;

    /// <summary>Raised when the channel is closed, including when the whole association goes down.</summary>
    public event Action? OnClosed;

    /// <summary>The channel label as negotiated by DCEP.</summary>
    public string Label { get; }

    /// <summary>The sub-protocol name as negotiated by DCEP; empty when none was given.</summary>
    public string Protocol { get; }

    /// <summary>True when messages are delivered to the peer in send order.</summary>
    public bool Ordered { get; }

    /// <summary>
    /// Retransmission limit per message, or null for full reliability. Zero means a message is
    /// transmitted exactly once and abandoned if it is lost.
    /// </summary>
    public ushort? MaxRetransmits { get; }

    /// <summary>The SCTP stream identifier carrying this channel.</summary>
    public int StreamId { get; }

    /// <summary>True when the peer sent the DATA_CHANNEL_OPEN that created this channel.</summary>
    public bool NegotiatedByPeer { get; }

    /// <summary>The channel's lifecycle state.</summary>
    public DataChannelState State { get; internal set; }

    /// <summary>
    /// Bytes of user payload queued for this channel that the peer has not yet acknowledged.
    /// Includes payload still waiting for the association to be established.
    /// </summary>
    public long BufferedAmount => Interlocked.Read(ref _bufferedAmount);

    /// <summary>Sends a binary message.</summary>
    /// <param name="payload">The message body. An empty payload is sent as PPID 57.</param>
    /// <exception cref="InvalidOperationException">The channel is closing or closed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The message exceeds the association's message size limit.</exception>
    public void Send(ReadOnlySpan<byte> payload)
    {
        EnsureSendable();
        _association.SendOnChannel(this, payload.IsEmpty ? SctpPpid.BinaryEmpty : SctpPpid.Binary, payload);
    }

    /// <summary>Sends a UTF-8 string message.</summary>
    /// <param name="text">The message text. An empty string is sent as PPID 56.</param>
    /// <exception cref="InvalidOperationException">The channel is closing or closed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The message exceeds the association's message size limit.</exception>
    public void SendText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        EnsureSendable();
        var bytes = Encoding.UTF8.GetBytes(text);
        _association.SendOnChannel(this, bytes.Length == 0 ? SctpPpid.StringEmpty : SctpPpid.String, bytes);
    }

    /// <summary>
    /// Closes the channel.
    /// </summary>
    /// <remarks>
    /// When the association negotiated RFC 6525 stream reconfiguration, this drives an outgoing
    /// RE-CONFIG that resets the channel's SCTP stream on the wire once its data has been
    /// acknowledged; <see cref="OnClosed"/> fires and the stream identifier is freed for reuse when
    /// the peer's response arrives. Until then the channel reports <see cref="DataChannelState.Closing"/>.
    /// When the peer did not negotiate RE-CONFIG the channel closes immediately without a wire reset.
    /// </remarks>
    public void Close()
    {
        if (State is DataChannelState.Closed or DataChannelState.Closing)
        {
            return;
        }

        _association.CloseChannel(this);
    }

    internal void AddBuffered(long delta) => Interlocked.Add(ref _bufferedAmount, delta);

    internal void RaiseOpen() => OnOpen?.Invoke();

    internal void RaiseClosed() => OnClosed?.Invoke();

    internal void RaiseMessage(bool isBinary, ReadOnlySpan<byte> payload) => OnMessage?.Invoke(isBinary, payload);

    internal bool HasMessageHandler => OnMessage is not null;

    private void EnsureSendable()
    {
        if (State is DataChannelState.Closing or DataChannelState.Closed)
        {
            throw new InvalidOperationException($"Data channel '{Label}' is {State}.");
        }
    }
}
