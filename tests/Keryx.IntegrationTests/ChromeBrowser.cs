using System.Diagnostics;

namespace Keryx.IntegrationTests;

/// <summary>Locates and launches the headless Chrome the browser interop tests drive.</summary>
internal static class ChromeBrowser
{
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

        chrome.StartInfo.ArgumentList.Add("--headless=new");
        chrome.StartInfo.ArgumentList.Add("--disable-gpu");
        chrome.StartInfo.ArgumentList.Add("--mute-audio");
        chrome.StartInfo.ArgumentList.Add("--no-first-run");
        chrome.StartInfo.ArgumentList.Add("--no-default-browser-check");
        chrome.StartInfo.ArgumentList.Add("--autoplay-policy=no-user-gesture-required");
        chrome.StartInfo.ArgumentList.Add($"--user-data-dir={userDataDir}");
        chrome.StartInfo.ArgumentList.Add(url);
        chrome.Start();
        return chrome;
    }

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
