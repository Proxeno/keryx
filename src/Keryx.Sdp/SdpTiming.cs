namespace Keryx.Sdp;

/// <summary>
/// A <c>t=</c> line together with any <c>r=</c> repeat lines that follow it. WebRTC always uses
/// <c>t=0 0</c>.
/// </summary>
public sealed class SdpTiming
{
    /// <summary>Creates <c>t=0 0</c>.</summary>
    public SdpTiming()
    {
    }

    /// <summary>Creates a timing line from raw start and stop fields.</summary>
    /// <param name="start">Start time field, verbatim.</param>
    /// <param name="stop">Stop time field, verbatim.</param>
    public SdpTiming(string start, string stop)
    {
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(stop);
        Start = start;
        Stop = stop;
    }

    /// <summary>Start time field, kept as text to preserve unusual values.</summary>
    public string Start { get; set; } = "0";

    /// <summary>Stop time field, kept as text to preserve unusual values.</summary>
    public string Stop { get; set; } = "0";

    /// <summary>Raw <c>r=</c> repeat values attached to this timing line, in document order.</summary>
    public IList<string> RepeatTimes { get; } = new List<string>();

    /// <summary>Renders the timing without the leading <c>t=</c>.</summary>
    /// <returns>For example <c>0 0</c>.</returns>
    public string ToLineValue() => Start + " " + Stop;

    /// <summary>Renders the <c>t=</c> line without a line terminator or repeat lines.</summary>
    /// <returns>For example <c>t=0 0</c>.</returns>
    public override string ToString() => "t=" + ToLineValue();
}
