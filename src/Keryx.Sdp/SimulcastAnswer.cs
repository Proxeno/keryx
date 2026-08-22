namespace Keryx.Sdp;

/// <summary>
/// The simulcast-specific parts of an answer to one offered simulcast m-section: the reversed
/// <c>a=simulcast</c> line, the <c>a=rid</c> declarations to echo, and the RID / repaired-RID / MID
/// <c>a=extmap</c>s that must be negotiated for demux to work. Produced by
/// <see cref="SdpNegotiator.AnswerSimulcast(MediaDescription, System.Func{string, bool}?)"/> and
/// applied to the answer's m-section by the caller.
/// </summary>
/// <param name="Simulcast">
/// The answerer's <c>a=simulcast</c>: the offered directions swapped (RFC 8853 §5.2), with unaccepted
/// RIDs pruned.
/// </param>
/// <param name="Rids">
/// The <c>a=rid</c> declarations for the RIDs the answerer kept, each with its direction reversed and
/// its restrictions preserved verbatim.
/// </param>
/// <param name="HeaderExtensions">
/// The RID / repaired-RID / MID <c>a=extmap</c>s echoed from the offer with their ids unchanged, so
/// the extensions are negotiated symmetrically. Empty when the RID extension was not offered, in which
/// case demux is impossible and the caller should treat the section as non-simulcast.
/// </param>
public sealed record SimulcastAnswer(
    SdpSimulcast Simulcast,
    IReadOnlyList<SdpRid> Rids,
    IReadOnlyList<SdpExtMap> HeaderExtensions)
{
    /// <summary>True when the RID header extension was negotiated, so RID-based demux is possible.</summary>
    public bool HasRidExtension
    {
        get
        {
            foreach (var extMap in HeaderExtensions)
            {
                if (string.Equals(extMap.Uri, RtpHeaderExtensionUri.Rid, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
