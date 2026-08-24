using System.Diagnostics;

namespace Keryx.IntegrationTests;

/// <summary>The real browser engines the interop lanes drive.</summary>
internal enum BrowserKind
{
    /// <summary>Google Chrome / Chromium, driven headless with a throwaway user-data dir.</summary>
    Chrome,

    /// <summary>Mozilla Firefox, driven headless with a throwaway profile primed for loopback WebRTC.</summary>
    Firefox,
}

/// <summary>
/// Locates and launches the headless browser an interop lane drives, parameterized by
/// <see cref="BrowserKind"/> so the one seam powers both the Chrome lane and the Firefox lane rather
/// than forking a launcher per engine. Each engine differs only in where it is installed, the
/// headless launch flags it takes, and — for Firefox — a profile primed with the prefs that make a
/// pure 127.0.0.1 loopback WebRTC handshake possible; everything above this seam (the HTTP signaling
/// host and the role-flexible <c>assets/chrome-client.html</c> fixture) is engine agnostic.
/// </summary>
internal static class BrowserLauncher
{
    /// <summary>The env var whose value <c>1</c> makes a missing browser a failure, per engine.</summary>
    /// <param name="kind">The engine.</param>
    /// <returns>The env var name.</returns>
    internal static string RequireEnvVar(BrowserKind kind) => kind switch
    {
        BrowserKind.Chrome => "KERYX_REQUIRE_CHROME",
        BrowserKind.Firefox => "KERYX_REQUIRE_FIREFOX",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    /// <summary>The env var that overrides the executable search, per engine.</summary>
    /// <param name="kind">The engine.</param>
    /// <returns>The env var name.</returns>
    internal static string PathEnvVar(BrowserKind kind) => kind switch
    {
        BrowserKind.Chrome => "KERYX_CHROME_PATH",
        BrowserKind.Firefox => "KERYX_FIREFOX_PATH",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    /// <summary>
    /// True when the environment demands this engine's interop tests actually run: the CI job that
    /// installs the browser sets its <c>KERYX_REQUIRE_*</c> gate to <c>1</c>. In that mode a missing
    /// or unlaunchable browser is a test failure, not a graceful skip — so an interop regression fails
    /// the build instead of silently passing. Local dev runs leave the variable unset and skip.
    /// </summary>
    /// <param name="kind">The engine.</param>
    /// <returns>True when the engine is required.</returns>
    internal static bool Required(BrowserKind kind) =>
        string.Equals(
            Environment.GetEnvironmentVariable(RequireEnvVar(kind)),
            "1",
            StringComparison.Ordinal);

    /// <summary>
    /// Resolves the browser to drive, honouring the CI contract: returns the executable path when the
    /// engine is present; returns <see langword="null"/> so the caller skips when none is installed and
    /// the engine is not required; throws when the engine is required but absent, turning the CI job's
    /// missing browser into a failure rather than a no-op pass.
    /// </summary>
    /// <param name="kind">The engine.</param>
    /// <returns>The executable path, or <see langword="null"/> when the caller should skip.</returns>
    /// <exception cref="InvalidOperationException">
    /// The engine's <c>KERYX_REQUIRE_*</c> gate is <c>1</c> but no browser could be located.
    /// </exception>
    internal static string? Require(BrowserKind kind)
    {
        var path = Find(kind);
        if (path is null && Required(kind))
        {
            throw new InvalidOperationException(
                $"{RequireEnvVar(kind)}=1 but no {kind} was found. The {kind} interop CI job guarantees a "
                + $"browser is installed, so its absence is a failure, not a skip. Set {PathEnvVar(kind)} "
                + $"or install {kind}.");
        }

        return path;
    }

    /// <summary>Finds an installed browser for the engine.</summary>
    /// <param name="kind">The engine.</param>
    /// <returns>The executable path, or null when the engine is not installed.</returns>
    /// <remarks>The engine's <c>KERYX_*_PATH</c> env var overrides the search.</remarks>
    internal static string? Find(BrowserKind kind)
    {
        var overridePath = Environment.GetEnvironmentVariable(PathEnvVar(kind));
        string[] candidates = kind switch
        {
            BrowserKind.Chrome =>
            [
                overridePath ?? string.Empty,
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/usr/bin/google-chrome",
                "/usr/bin/google-chrome-stable",
                "/usr/bin/chromium",
            ],
            BrowserKind.Firefox =>
            [
                overridePath ?? string.Empty,
                "/Applications/Firefox.app/Contents/MacOS/firefox",
                "/usr/bin/firefox",
                "/usr/local/bin/firefox",
                "/snap/bin/firefox",
            ],
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        return candidates.FirstOrDefault(p => p.Length > 0 && File.Exists(p));
    }

    /// <summary>
    /// Starts the headless browser on a page, in a throwaway profile. For Firefox the profile is
    /// primed first (see <see cref="PrimeFirefoxProfile"/>) so its <c>RTCPeerConnection</c> gathers
    /// 127.0.0.1 host candidates and can encode/decode H.264.
    /// </summary>
    /// <param name="kind">The engine.</param>
    /// <param name="executablePath">The browser to run.</param>
    /// <param name="url">The page to open.</param>
    /// <param name="profileDir">A directory for the throwaway profile; the caller deletes it.</param>
    /// <returns>The started process.</returns>
    internal static Process Launch(BrowserKind kind, string executablePath, string url, string profileDir)
    {
        if (kind == BrowserKind.Firefox)
        {
            PrimeFirefoxProfile(profileDir);
        }

        var browser = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            },
        };

        foreach (var argument in Arguments(kind, url, profileDir))
        {
            browser.StartInfo.ArgumentList.Add(argument);
        }

        browser.Start();
        return browser;
    }

    /// <summary>
    /// The headless launch flags an engine's interop tests share.
    /// <para>
    /// Chrome: <c>--no-sandbox</c> and <c>--disable-dev-shm-usage</c> are what let headless Chrome
    /// start inside a CI container (a restricted user namespace and a tiny <c>/dev/shm</c> would
    /// otherwise abort launch); both are harmless in the throwaway test profile locally.
    /// </para>
    /// <para>
    /// Firefox takes the page as a positional argument under <c>--headless</c>, with
    /// <c>--no-remote --new-instance</c> so a serial test never attaches to another Firefox, and
    /// <c>--profile</c> pointing at the primed throwaway profile.
    /// </para>
    /// </summary>
    /// <param name="kind">The engine.</param>
    /// <param name="url">The page to open.</param>
    /// <param name="profileDir">A directory for the throwaway profile.</param>
    /// <returns>The argument list, in order.</returns>
    internal static IEnumerable<string> Arguments(BrowserKind kind, string url, string profileDir) => kind switch
    {
        BrowserKind.Chrome =>
        [
            "--headless=new",
            "--disable-gpu",
            "--mute-audio",
            "--no-first-run",
            "--no-default-browser-check",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--autoplay-policy=no-user-gesture-required",
            $"--user-data-dir={profileDir}",
            url,
        ],
        BrowserKind.Firefox =>
        [
            "--headless",
            "--no-remote",
            "--new-instance",
            "--profile",
            profileDir,
            url,
        ],
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    /// <summary>
    /// Writes the <c>user.js</c> that turns a fresh Firefox profile into one that can complete a pure
    /// 127.0.0.1 loopback WebRTC handshake headless, and copies a warmed OpenH264 GMP into it when one
    /// is offered. Firefox's defaults fight loopback interop in three ways this undoes:
    /// <list type="bullet">
    /// <item><c>media.peerconnection.ice.loopback=true</c> — Firefox does not gather loopback (127.0.0.1)
    /// host candidates unless asked; without it ICE never connects on a pure loopback path.</item>
    /// <item><c>media.peerconnection.ice.obfuscate_host_addresses=false</c> — disables the mDNS
    /// <c>.local</c> candidate hiding that would otherwise replace the real 127.0.0.1 address.</item>
    /// <item>the <c>media.gmp-gmpopenh264.*</c> prefs enable the OpenH264 GMP so Firefox can offer,
    /// answer, encode and decode H.264 — the only video codec Keryx speaks.</item>
    /// </list>
    /// The remaining prefs silence first-run, telemetry and update chatter that would otherwise add
    /// latency and network noise to a headless CI launch.
    /// </summary>
    /// <param name="profileDir">The profile directory to create and prime.</param>
    internal static void PrimeFirefoxProfile(string profileDir)
    {
        Directory.CreateDirectory(profileDir);

        // A warmed template profile (created once by the CI job so the OpenH264 GMP is already
        // downloaded) lets every throwaway profile speak H.264 without racing a per-test Cisco
        // download. Local dev without the template relies on Firefox's own on-demand GMP fetch.
        var gmpTemplate = Environment.GetEnvironmentVariable("KERYX_FIREFOX_GMP_DIR");
        if (!string.IsNullOrEmpty(gmpTemplate))
        {
            CopyOpenH264Gmp(gmpTemplate, profileDir);
        }

        string[] prefs =
        [
            // ---- WebRTC loopback + H.264, the prefs that make keryx interop possible ----
            Pref("media.peerconnection.ice.loopback", true),
            Pref("media.peerconnection.ice.obfuscate_host_addresses", false),
            Pref("media.peerconnection.ice.no_host", false),
            Pref("media.peerconnection.enabled", true),
            Pref("media.peerconnection.video.h264_enabled", true),
            Pref("media.navigator.mediadatadecoder_h264_enabled", true),
            Pref("media.gmp-gmpopenh264.enabled", true),
            Pref("media.gmp-gmpopenh264.autoupdate", true),
            Pref("media.gmp-manager.updateEnabled", true),
            Pref("media.navigator.permission.disabled", true),
            Pref("media.autoplay.default", 0),
            Pref("media.autoplay.blocking_policy", 0),
            // ---- headless hygiene: no first-run, telemetry, or update traffic ----
            Pref("browser.shell.checkDefaultBrowser", false),
            Pref("browser.startup.homepage_override.mstone", "ignore"),
            Pref("startup.homepage_welcome_url", "about:blank"),
            Pref("startup.homepage_welcome_url.additional", string.Empty),
            Pref("datareporting.policy.dataSubmissionEnabled", false),
            Pref("datareporting.healthreport.uploadEnabled", false),
            Pref("toolkit.telemetry.enabled", false),
            Pref("app.update.enabled", false),
            Pref("app.update.auto", false),
            Pref("extensions.update.enabled", false),
            Pref("dom.disable_beforeunload", true),
        ];

        File.WriteAllText(Path.Combine(profileDir, "user.js"), string.Join('\n', prefs) + '\n');
    }

    /// <summary>Renders one <c>user_pref</c> line with a boolean value.</summary>
    /// <param name="name">The preference name.</param>
    /// <param name="value">The boolean value.</param>
    /// <returns>The <c>user_pref(...);</c> line.</returns>
    private static string Pref(string name, bool value) =>
        $"user_pref(\"{name}\", {(value ? "true" : "false")});";

    /// <summary>Renders one <c>user_pref</c> line with an integer value.</summary>
    /// <param name="name">The preference name.</param>
    /// <param name="value">The integer value.</param>
    /// <returns>The <c>user_pref(...);</c> line.</returns>
    private static string Pref(string name, int value) =>
        $"user_pref(\"{name}\", {value.ToString(System.Globalization.CultureInfo.InvariantCulture)});";

    /// <summary>Renders one <c>user_pref</c> line with a string value.</summary>
    /// <param name="name">The preference name.</param>
    /// <param name="value">The string value.</param>
    /// <returns>The <c>user_pref(...);</c> line.</returns>
    private static string Pref(string name, string value) =>
        $"user_pref(\"{name}\", \"{value}\");";

    /// <summary>
    /// Copies the <c>gmp-gmpopenh264</c> plugin tree from a warmed template profile into a throwaway
    /// profile, so the throwaway can encode/decode H.264 immediately instead of racing an on-demand
    /// download. Best effort: a missing template simply leaves Firefox to fetch the GMP itself.
    /// </summary>
    /// <param name="templateProfileDir">The warmed profile that already holds the GMP.</param>
    /// <param name="profileDir">The throwaway profile to copy it into.</param>
    private static void CopyOpenH264Gmp(string templateProfileDir, string profileDir)
    {
        try
        {
            var source = Path.Combine(templateProfileDir, "gmp-gmpopenh264");
            if (!Directory.Exists(source))
            {
                return;
            }

            var destination = Path.Combine(profileDir, "gmp-gmpopenh264");
            foreach (var dir in Directory.GetDirectories(source, "*", SearchOption.AllDirectories))
            {
                Directory.CreateDirectory(dir.Replace(source, destination, StringComparison.Ordinal));
            }

            foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
            {
                File.Copy(file, file.Replace(source, destination, StringComparison.Ordinal), overwrite: true);
            }
        }
        catch (Exception)
        {
            // best effort: fall back to Firefox's own on-demand GMP download
        }
    }

    /// <summary>Kills the browser and deletes its profile directory; never throws.</summary>
    /// <param name="browser">The browser process, or null.</param>
    /// <param name="profileDir">The profile directory to remove.</param>
    internal static void Cleanup(Process? browser, string profileDir)
    {
        try
        {
            if (browser is { HasExited: false })
            {
                browser.Kill(entireProcessTree: true);
            }
        }
        catch (Exception)
        {
            // best effort
        }

        try
        {
            Directory.Delete(profileDir, recursive: true);
        }
        catch (Exception)
        {
            // best effort
        }
    }
}
