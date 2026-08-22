using System.Text;

namespace Keryx.Sdp;

/// <summary>
/// One RID alternative inside a simulcast stream description (RFC 8853 §5.1 <c>sc-id</c>): a RID
/// identifier, optionally prefixed with <c>~</c> to mark the stream initially paused.
/// </summary>
/// <param name="Id">The RID identifier this alternative refers to.</param>
/// <param name="Paused">True when the <c>~</c> prefix marks the stream as initially paused.</param>
public sealed record SdpSimulcastAlternative(string Id, bool Paused = false)
{
    /// <summary>Renders the alternative as it appears in the <c>a=simulcast</c> value.</summary>
    /// <returns>For example <c>hi</c> or <c>~hi</c>.</returns>
    public override string ToString() => Paused ? "~" + Id : Id;
}

/// <summary>
/// One simulcast stream (RFC 8853 §5.1 <c>sc-alt-list</c>): an ordered list of RID alternatives. Only
/// one alternative is active at a time; the list expresses that the sender may pick any of them.
/// </summary>
/// <param name="Alternatives">The alternatives, in preference order. Always at least one.</param>
public sealed record SdpSimulcastStream(IReadOnlyList<SdpSimulcastAlternative> Alternatives)
{
    /// <summary>Creates a single-alternative stream from one RID.</summary>
    /// <param name="id">The RID identifier.</param>
    /// <param name="paused">Whether the stream is initially paused.</param>
    public SdpSimulcastStream(string id, bool paused = false)
        : this(new[] { new SdpSimulcastAlternative(id, paused) })
    {
    }

    /// <summary>Renders the stream as it appears in the <c>a=simulcast</c> value.</summary>
    /// <returns>For example <c>hi</c> or <c>hi,mid</c>.</returns>
    public override string ToString() => string.Join(',', Alternatives);
}

/// <summary>
/// An <c>a=simulcast</c> line (RFC 8853 §5.1): the set of simulcast streams offered in each direction.
/// The <c>send</c> list names the simulcast layers a sender will transmit — for a broadcast ingest,
/// the creator's high/medium/low video encodings — each identified by a RID declared in an
/// <c>a=rid</c> line.
/// </summary>
/// <param name="Send">Streams in the <c>send</c> direction, in document order; empty when absent.</param>
/// <param name="Recv">Streams in the <c>recv</c> direction, in document order; empty when absent.</param>
public sealed record SdpSimulcast(
    IReadOnlyList<SdpSimulcastStream> Send,
    IReadOnlyList<SdpSimulcastStream> Recv)
{
    private const string SendToken = "send";
    private const string RecvToken = "recv";

    /// <summary>Creates a send-only simulcast description.</summary>
    /// <param name="send">The streams in the <c>send</c> direction.</param>
    /// <returns>A description with an empty <c>recv</c> list.</returns>
    public static SdpSimulcast SendOnly(params SdpSimulcastStream[] send)
    {
        ArgumentNullException.ThrowIfNull(send);
        return new SdpSimulcast(send, Array.Empty<SdpSimulcastStream>());
    }

    /// <summary>
    /// Produces the answerer's view of an offered simulcast description by swapping the directions:
    /// what the offerer sends, the answerer receives, and vice versa (RFC 8853 §5.2). Selection of
    /// which offered layers to keep is a policy decision left to the caller.
    /// </summary>
    /// <returns>A description with <see cref="Send"/> and <see cref="Recv"/> exchanged.</returns>
    public SdpSimulcast Reversed() => new(Recv, Send);

    /// <summary>Parses an <c>a=simulcast</c> attribute value. Never throws.</summary>
    /// <param name="value">The attribute value, without the <c>a=simulcast:</c> prefix.</param>
    /// <param name="simulcast">Receives the parsed description.</param>
    /// <returns>True when at least one valid <c>send</c> or <c>recv</c> direction is present.</returns>
    public static bool TryParse(string? value, out SdpSimulcast? simulcast)
    {
        simulcast = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var tokens = value.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        IReadOnlyList<SdpSimulcastStream>? send = null;
        IReadOnlyList<SdpSimulcastStream>? recv = null;

        var i = 0;
        while (i + 1 < tokens.Length)
        {
            var direction = tokens[i];
            var list = ParseStreamList(tokens[i + 1]);
            if (string.Equals(direction, SendToken, StringComparison.Ordinal) && send is null)
            {
                send = list;
            }
            else if (string.Equals(direction, RecvToken, StringComparison.Ordinal) && recv is null)
            {
                recv = list;
            }
            else
            {
                return false;
            }

            i += 2;
        }

        if (i != tokens.Length || (send is null && recv is null))
        {
            return false;
        }

        simulcast = new SdpSimulcast(
            send ?? Array.Empty<SdpSimulcastStream>(),
            recv ?? Array.Empty<SdpSimulcastStream>());
        return true;
    }

    private static IReadOnlyList<SdpSimulcastStream> ParseStreamList(string text)
    {
        var streams = new List<SdpSimulcastStream>();
        foreach (var streamText in text.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var alternatives = new List<SdpSimulcastAlternative>();
            foreach (var altText in streamText.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                var paused = altText.StartsWith('~');
                var id = paused ? altText[1..] : altText;
                if (id.Length != 0)
                {
                    alternatives.Add(new SdpSimulcastAlternative(id, paused));
                }
            }

            if (alternatives.Count != 0)
            {
                streams.Add(new SdpSimulcastStream(alternatives));
            }
        }

        return streams;
    }

    /// <summary>Renders the value part of the <c>a=simulcast</c> attribute.</summary>
    /// <returns>For example <c>send hi;mid;lo</c>.</returns>
    public string ToAttributeValue()
    {
        var builder = new StringBuilder();
        if (Send.Count != 0)
        {
            builder.Append(SendToken).Append(' ').Append(string.Join(';', Send));
        }

        if (Recv.Count != 0)
        {
            if (builder.Length != 0)
            {
                builder.Append(' ');
            }

            builder.Append(RecvToken).Append(' ').Append(string.Join(';', Recv));
        }

        return builder.ToString();
    }

    /// <summary>Renders the complete attribute without a line terminator.</summary>
    /// <returns>For example <c>a=simulcast:send hi;mid;lo</c>.</returns>
    public override string ToString() => "a=simulcast:" + ToAttributeValue();
}
