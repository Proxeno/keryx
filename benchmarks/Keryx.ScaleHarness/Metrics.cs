using System.Diagnostics;

namespace Keryx.ScaleHarness;

/// <summary>A point-in-time snapshot of process resource counters, differenced to measure a workload.</summary>
internal readonly record struct MetricsSnapshot(
    long TimestampTicks,
    TimeSpan ProcessorTime,
    long AllocatedBytes,
    int Gen0,
    int Gen1,
    int Gen2,
    TimeSpan GcPause,
    long ManagedBytes,
    long WorkingSetBytes,
    int ThreadCount)
{
    public static MetricsSnapshot Capture(bool collectManaged = false)
    {
        var process = Process.GetCurrentProcess();
        process.Refresh();
        return new MetricsSnapshot(
            Stopwatch.GetTimestamp(),
            process.TotalProcessorTime,
            GC.GetTotalAllocatedBytes(precise: false),
            GC.CollectionCount(0),
            GC.CollectionCount(1),
            GC.CollectionCount(2),
            GC.GetTotalPauseDuration(),
            GC.GetTotalMemory(forceFullCollection: collectManaged),
            process.WorkingSet64,
            process.Threads.Count);
    }
}

/// <summary>The differences between two <see cref="MetricsSnapshot"/> captures, plus derived rates.</summary>
internal sealed class MetricsDelta
{
    public required TimeSpan Wall { get; init; }
    public required TimeSpan Processor { get; init; }
    public required long AllocatedBytes { get; init; }
    public required int Gen0 { get; init; }
    public required int Gen1 { get; init; }
    public required int Gen2 { get; init; }
    public required TimeSpan GcPause { get; init; }
    public required long ManagedBytes { get; init; }
    public required long WorkingSetBytes { get; init; }
    public required int ThreadCount { get; init; }

    /// <summary>CPU utilisation as a fraction of one core (e.g. 12.0 means 12 cores fully busy).</summary>
    public double CpuCores => Wall.TotalSeconds > 0 ? Processor.TotalSeconds / Wall.TotalSeconds : 0;

    public double AllocMBPerSec => Wall.TotalSeconds > 0 ? AllocatedBytes / 1e6 / Wall.TotalSeconds : 0;

    public static MetricsDelta Between(MetricsSnapshot start, MetricsSnapshot end) => new()
    {
        Wall = Stopwatch.GetElapsedTime(start.TimestampTicks, end.TimestampTicks),
        Processor = end.ProcessorTime - start.ProcessorTime,
        AllocatedBytes = end.AllocatedBytes - start.AllocatedBytes,
        Gen0 = end.Gen0 - start.Gen0,
        Gen1 = end.Gen1 - start.Gen1,
        Gen2 = end.Gen2 - start.Gen2,
        GcPause = end.GcPause - start.GcPause,
        ManagedBytes = end.ManagedBytes - start.ManagedBytes,
        WorkingSetBytes = end.WorkingSetBytes - start.WorkingSetBytes,
        ThreadCount = end.ThreadCount - start.ThreadCount,
    };
}
