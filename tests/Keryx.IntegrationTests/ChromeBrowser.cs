using System.Diagnostics;

namespace Keryx.IntegrationTests;

/// <summary>Locates and launches the headless Chrome the browser interop tests drive.</summary>
internal static class ChromeBrowser
{
    /// <summary>
    /// True when the environment demands the browser interop tests actually run: the CI job that
    /// installs headless Chrome sets <c>KERYX_REQUIRE_CHROME=1</c>. In that mode a missing or
    /// unlaunchable browser is a test failure, not a graceful skip — so an interop regression fails
    /// the build instead of silently passing. Local dev runs leave the variable unset and skip.
    /// </summary>
    internal static bool ChromeRequired =>
        string.Equals(
            Environment.GetEnvironmentVariable("KERYX_REQUIRE_CHROME"),
            "1",
            StringComparison.Ordinal);

    /// <summary>
    /// Resolves the browser to drive, honouring the CI contract: returns the executable path when a
    /// browser is present; returns <see langword="null"/> so the caller skips when none is installed
    /// and Chrome is not required; throws when Chrome is required but absent, turning the CI job's
    /// missing browser into a failure rather than a no-op pass.
    /// </summary>
    /// <returns>The executable path, or <see langword="null"/> when the caller should skip.</returns>
    /// <exception cref="InvalidOperationException">
    /// <c>KERYX_REQUIRE_CHROME=1</c> but no browser could be located.
    /// </exception>
    internal static string? Require()
    {
        var path = Find();
        if (path is null && ChromeRequired)
        {
            throw new InvalidOperationException(
                "KERYX_REQUIRE_CHROME=1 but no Chrome/Chromium was found. The browser interop CI job "
                + "guarantees a browser is installed, so its absence is a failure, not a skip. Set "
                + "KERYX_CHROME_PATH or install Chrome.");
        }

        return path;
    }

    /// <summary>Finds an installed Chrome or Chromium.</summary>
    /// <returns>The executable path, or null when no browser is installed.</returns>
    /// <remarks><c>KERYX_CHROME_PATH</c> overrides the search.</remarks>
    internal static string? Find()
    {
        var overridePath = Environment.GetEnvironmentVariable("KERYX_CHROME_PATH");
        string[] candidates =
        [
            overridePath ?? string.Empty,
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium",
        ];
        return candidates.FirstOrDefault(p => p.Length > 0 && File.Exists(p));
    }

    /// <summary>Starts headless Chrome on a page, in a throwaway profile.</summary>
    /// <param name="executablePath">The browser to run.</param>
    /// <param name="url">The page to open.</param>
    /// <param name="userDataDir">A directory for the throwaway profile; the caller deletes it.</param>
    /// <returns>The started process.</returns>
    internal static Process Launch(string executablePath, string url, string userDataDir)
    {
        var chrome = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            },
        };

        foreach (var argument in Arguments(url, userDataDir))
        {
            chrome.StartInfo.ArgumentList.Add(argument);
        }

        chrome.Start();
        return chrome;
    }

    /// <summary>
    /// The headless launch flags every interop test shares. <c>--no-sandbox</c> and
    /// <c>--disable-dev-shm-usage</c> are what let headless Chrome start inside a CI container (a
    /// restricted user namespace and a tiny <c>/dev/shm</c> would otherwise abort launch); both are
    /// harmless in the throwaway test profile locally.
    /// </summary>
    /// <param name="url">The page to open.</param>
    /// <param name="userDataDir">A directory for the throwaway profile.</param>
    /// <returns>The argument list, in order.</returns>
    internal static IEnumerable<string> Arguments(string url, string userDataDir) =>
    [
        "--headless=new",
        "--disable-gpu",
        "--mute-audio",
        "--no-first-run",
        "--no-default-browser-check",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--autoplay-policy=no-user-gesture-required",
        $"--user-data-dir={userDataDir}",
        url,
    ];

    /// <summary>Kills the browser and deletes its profile directory; never throws.</summary>
    /// <param name="chrome">The browser process, or null.</param>
    /// <param name="userDataDir">The profile directory to remove.</param>
    internal static void Cleanup(Process? chrome, string userDataDir)
    {
        try
        {
            if (chrome is { HasExited: false })
            {
                chrome.Kill(entireProcessTree: true);
            }
        }
        catch (Exception)
        {
            // best effort
        }

        try
        {
            Directory.Delete(userDataDir, recursive: true);
        }
        catch (Exception)
        {
            // best effort
        }
    }
}
