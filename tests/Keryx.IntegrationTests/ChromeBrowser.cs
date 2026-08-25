using System.Diagnostics;

namespace Keryx.IntegrationTests;

/// <summary>
/// The Chrome-shaped facade over the shared <see cref="BrowserLauncher"/> seam, kept so the Chrome
/// interop tests read against a Chrome-named API. Every member forwards to
/// <see cref="BrowserLauncher"/> with <see cref="BrowserKind.Chrome"/>: the launch logic lives in one
/// seam that also drives Firefox, rather than a launcher forked per engine.
/// </summary>
internal static class ChromeBrowser
{
    /// <summary>
    /// True when <c>KERYX_REQUIRE_CHROME=1</c>: a missing browser then fails the build instead of
    /// skipping. See <see cref="BrowserLauncher.Required"/>.
    /// </summary>
    internal static bool ChromeRequired => BrowserLauncher.Required(BrowserKind.Chrome);

    /// <summary>Resolves the Chrome to drive, or throws when required but absent.</summary>
    /// <returns>The executable path, or <see langword="null"/> when the caller should skip.</returns>
    internal static string? Require() => BrowserLauncher.Require(BrowserKind.Chrome);

    /// <summary>Finds an installed Chrome or Chromium (<c>KERYX_CHROME_PATH</c> overrides).</summary>
    /// <returns>The executable path, or null when no browser is installed.</returns>
    internal static string? Find() => BrowserLauncher.Find(BrowserKind.Chrome);

    /// <summary>Starts headless Chrome on a page, in a throwaway profile.</summary>
    /// <param name="executablePath">The browser to run.</param>
    /// <param name="url">The page to open.</param>
    /// <param name="userDataDir">A directory for the throwaway profile; the caller deletes it.</param>
    /// <returns>The started process.</returns>
    internal static Process Launch(string executablePath, string url, string userDataDir) =>
        BrowserLauncher.Launch(BrowserKind.Chrome, executablePath, url, userDataDir);

    /// <summary>The headless launch flags every Chrome interop test shares.</summary>
    /// <param name="url">The page to open.</param>
    /// <param name="userDataDir">A directory for the throwaway profile.</param>
    /// <returns>The argument list, in order.</returns>
    internal static IEnumerable<string> Arguments(string url, string userDataDir) =>
        BrowserLauncher.Arguments(BrowserKind.Chrome, url, userDataDir);

    /// <summary>Kills the browser and deletes its profile directory; never throws.</summary>
    /// <param name="chrome">The browser process, or null.</param>
    /// <param name="userDataDir">The profile directory to remove.</param>
    internal static void Cleanup(Process? chrome, string userDataDir) =>
        BrowserLauncher.Cleanup(chrome, userDataDir);
}
