using BenchmarkDotNet.Running;

// Runs the Keryx micro-benchmarks. With no arguments BenchmarkDotNet shows the interactive picker;
// pass `--filter *` to run everything, or `--filter *Srtp*` to run one class. See README.md.
BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);

/// <summary>Entry-point anchor type for <see cref="BenchmarkSwitcher.FromAssembly"/>.</summary>
public partial class Program
{
    private Program()
    {
    }
}
