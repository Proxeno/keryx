namespace Keryx.Core;

/// <summary>Severity of a <see cref="IKeryxLogger"/> message.</summary>
public enum KeryxLogLevel
{
    /// <summary>Per-packet detail; enabled only when diagnosing wire-level issues.</summary>
    Trace = 0,

    /// <summary>Verbose diagnostic flow (state transitions, negotiated parameters).</summary>
    Debug = 1,

    /// <summary>Lifecycle events worth recording in production (connected, closed).</summary>
    Info = 2,

    /// <summary>Recoverable anomalies (ignored malformed packet, retransmission).</summary>
    Warning = 3,

    /// <summary>Failures that terminate a connection or operation.</summary>
    Error = 4,
}

/// <summary>
/// Minimal logging seam so the shipping libraries carry no dependency on any logging framework.
/// Hosts adapt this to their logger of choice; <see cref="NullLogger"/> is the default.
/// </summary>
public interface IKeryxLogger
{
    /// <summary>True when messages at <paramref name="level"/> will be recorded.</summary>
    bool IsEnabled(KeryxLogLevel level);

    /// <summary>Records one message. <paramref name="exception"/> accompanies failures.</summary>
    void Log(KeryxLogLevel level, string message, Exception? exception = null);
}

/// <summary>An <see cref="IKeryxLogger"/> that discards everything.</summary>
public sealed class NullLogger : IKeryxLogger
{
    /// <summary>The shared instance.</summary>
    public static NullLogger Instance { get; } = new();

    private NullLogger()
    {
    }

    /// <inheritdoc />
    public bool IsEnabled(KeryxLogLevel level) => false;

    /// <inheritdoc />
    public void Log(KeryxLogLevel level, string message, Exception? exception = null)
    {
    }
}

/// <summary>An <see cref="IKeryxLogger"/> that writes single-line messages to a <see cref="TextWriter"/>.</summary>
public sealed class TextWriterLogger : IKeryxLogger
{
    private readonly TextWriter _writer;
    private readonly KeryxLogLevel _minimum;
    private readonly string _name;

    /// <summary>Creates a logger writing to <paramref name="writer"/> at <paramref name="minimum"/> or above.</summary>
    public TextWriterLogger(TextWriter writer, KeryxLogLevel minimum = KeryxLogLevel.Info, string name = "keryx")
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(name);
        _writer = writer;
        _minimum = minimum;
        _name = name;
    }

    /// <inheritdoc />
    public bool IsEnabled(KeryxLogLevel level) => level >= _minimum;

    /// <inheritdoc />
    public void Log(KeryxLogLevel level, string message, Exception? exception = null)
    {
        if (!IsEnabled(level))
        {
            return;
        }

        var line = exception is null
            ? $"{DateTimeOffset.UtcNow:O} [{level}] {_name}: {message}"
            : $"{DateTimeOffset.UtcNow:O} [{level}] {_name}: {message} | {exception.GetType().Name}: {exception.Message}";
        lock (_writer)
        {
            _writer.WriteLine(line);
        }
    }
}
