using System.Diagnostics;

namespace Keryx.IntegrationTests;

/// <summary>
/// Locates, builds, and launches the Go/pion reference-implementation peer the
/// <see cref="PionInteropTests"/> drive (source under <c>tests/interop/pion</c>).
/// </summary>
/// <remarks>
/// The CI job builds the peer with <c>go build</c> and points the tests at the binary via
/// <c>KERYX_PION_PEER</c>; local dev with Go on PATH builds it on demand instead. Local dev
/// without Go skips — unless <c>KERYX_REQUIRE_PION=1</c> (the CI contract), which turns a missing
/// toolchain or peer into a failure so an interop regression fails the build instead of passing.
/// </remarks>
internal static class PionPeer
{
    /// <summary>
    /// True when the environment demands the pion interop tests actually run: the CI job that
    /// installs Go and builds the peer sets <c>KERYX_REQUIRE_PION=1</c>. In that mode a missing Go
    /// toolchain or unbuildable peer is a test failure, not a graceful skip. Local dev leaves the
    /// variable unset and skips.
    /// </summary>
    internal static bool PionRequired =>
        string.Equals(
            Environment.GetEnvironmentVariable("KERYX_REQUIRE_PION"),
            "1",
            StringComparison.Ordinal);

    /// <summary>
    /// Resolves the pion peer executable, honouring the CI contract: returns a prebuilt binary when
    /// <c>KERYX_PION_PEER</c> points at one; otherwise builds from source when Go is available;
    /// returns <see langword="null"/> so the caller skips when neither is possible and pion is not
    /// required; throws when pion is required but cannot be produced.
    /// </summary>
    /// <param name="output">Where build diagnostics land.</param>
    /// <returns>The executable path, or <see langword="null"/> when the caller should skip.</returns>
    /// <exception cref="InvalidOperationException"><c>KERYX_REQUIRE_PION=1</c> but no peer could be produced.</exception>
    internal static string? Require(Action<string> output)
    {
        var prebuilt = Environment.GetEnvironmentVariable("KERYX_PION_PEER");
        if (!string.IsNullOrEmpty(prebuilt) && File.Exists(prebuilt))
        {
            return prebuilt;
        }

        var sourceDir = FindSourceDir();
        var go = FindGo();
        if (sourceDir is not null && go is not null)
        {
            var built = Build(go, sourceDir, output);
            if (built is not null)
            {
                return built;
            }
        }

        if (PionRequired)
        {
            throw new InvalidOperationException(
                "KERYX_REQUIRE_PION=1 but the pion peer could not be produced. The pion interop CI job "
                + "installs Go and builds tests/interop/pion, so its absence is a failure, not a skip. "
                + $"Set KERYX_PION_PEER to a prebuilt binary or install Go (go={go ?? "not found"}, "
                + $"source={sourceDir ?? "not found"}).");
        }

        return null;
    }

    /// <summary>Walks up from the test binary to the <c>tests/interop/pion</c> source directory.</summary>
    /// <returns>The source directory, or null when it cannot be located.</returns>
    /// <remarks><c>KERYX_PION_DIR</c> overrides the search.</remarks>
    internal static string? FindSourceDir()
    {
        var overrideDir = Environment.GetEnvironmentVariable("KERYX_PION_DIR");
        if (!string.IsNullOrEmpty(overrideDir) && File.Exists(Path.Combine(overrideDir, "main.go")))
        {
            return overrideDir;
        }

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "tests", "interop", "pion");
            if (File.Exists(Path.Combine(candidate, "main.go")))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        return null;
    }

    /// <summary>Finds the Go toolchain.</summary>
    /// <returns>The <c>go</c> executable path, or null when Go is not installed.</returns>
    /// <remarks><c>KERYX_GO_PATH</c> overrides the search.</remarks>
    internal static string? FindGo()
    {
        var overridePath = Environment.GetEnvironmentVariable("KERYX_GO_PATH");
        var candidates = new List<string>();
        if (!string.IsNullOrEmpty(overridePath))
        {
            candidates.Add(overridePath);
        }

        candidates.Add("/usr/local/go/bin/go");
        candidates.Add("/opt/homebrew/bin/go");
        candidates.Add("/usr/lib/go/bin/go");
        candidates.Add("/usr/bin/go");

        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var part in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            candidates.Add(Path.Combine(part, "go"));
        }

        return candidates.FirstOrDefault(File.Exists);
    }

    /// <summary>
    /// Builds the peer with <c>go mod tidy</c> (resolves and pins deps, writes <c>go.sum</c>) then
    /// <c>go build</c>, into a temp output file.
    /// </summary>
    /// <param name="go">The Go toolchain path.</param>
    /// <param name="sourceDir">The peer source directory.</param>
    /// <param name="output">Where build diagnostics land.</param>
    /// <returns>The built executable path, or null when the build failed.</returns>
    internal static string? Build(string go, string sourceDir, Action<string> output)
    {
        var exe = OperatingSystem.IsWindows() ? ".exe" : string.Empty;
        var outputPath = Path.Combine(Path.GetTempPath(), $"keryx-pion-peer-{Guid.NewGuid():N}{exe}");

        if (!Run(go, ["mod", "tidy"], sourceDir, output)
            || !Run(go, ["build", "-o", outputPath, "."], sourceDir, output))
        {
            return null;
        }

        return File.Exists(outputPath) ? outputPath : null;
    }

    private static bool Run(string fileName, IEnumerable<string> args, string workingDir, Action<string> output)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                WorkingDirectory = workingDir,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            },
        };
        foreach (var arg in args)
        {
            process.StartInfo.ArgumentList.Add(arg);
        }

        // Let `go build` add any missing module requirements/sums (mirrors the CI `go mod tidy`).
        process.StartInfo.Environment["GOFLAGS"] = "-mod=mod";

        process.Start();
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit(180_000);

        if (process.ExitCode != 0)
        {
            output($"go {string.Join(' ', args)} failed ({process.ExitCode}): {stderr}{stdout}");
            return false;
        }

        return true;
    }

    /// <summary>Launches the peer against the signaling host on the loopback port range.</summary>
    /// <param name="executablePath">The peer binary.</param>
    /// <param name="signalUrl">The base signaling URL, e.g. <c>http://127.0.0.1:7984</c>.</param>
    /// <param name="portMin">Lowest UDP port the peer may bind for ICE host candidates.</param>
    /// <param name="portMax">Highest UDP port the peer may bind.</param>
    /// <returns>The started process.</returns>
    internal static Process Launch(string executablePath, string signalUrl, int portMin, int portMax)
    {
        var peer = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            },
        };
        foreach (var arg in new[]
                 {
                     "-signal", signalUrl,
                     "-role", "answer",
                     "-port-min", portMin.ToString(),
                     "-port-max", portMax.ToString(),
                 })
        {
            peer.StartInfo.ArgumentList.Add(arg);
        }

        peer.Start();
        return peer;
    }

    /// <summary>Kills the peer process; never throws.</summary>
    /// <param name="peer">The peer process, or null.</param>
    internal static void Cleanup(Process? peer)
    {
        try
        {
            if (peer is { HasExited: false })
            {
                peer.Kill(entireProcessTree: true);
            }
        }
        catch (Exception)
        {
            // best effort
        }
    }
}
