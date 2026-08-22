namespace Keryx.Sdp;

/// <summary>
/// Helpers for the <c>key=value;key=value</c> format most WebRTC codecs use inside <c>a=fmtp</c>.
/// </summary>
/// <remarks>
/// Not every codec uses this shape (<c>a=fmtp:101 0-16</c> for telephone-event, for instance), so the
/// raw fmtp string stays available on the media description and these helpers are strictly a
/// convenience layer. Tokens without <c>=</c> parse to a key with an empty value.
/// </remarks>
public static class FmtpParameters
{
    /// <summary>Splits an fmtp parameter string into key/value pairs, preserving document order.</summary>
    /// <param name="parameters">The raw fmtp parameter string, or <see langword="null"/>.</param>
    /// <returns>An ordinal, case-sensitive lookup; empty when <paramref name="parameters"/> is blank.</returns>
    public static IReadOnlyDictionary<string, string> Parse(string? parameters)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(parameters))
        {
            return result;
        }

        foreach (var token in parameters.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var equals = token.IndexOf('=');
            if (equals < 0)
            {
                result[token] = string.Empty;
            }
            else
            {
                result[token[..equals].Trim()] = token[(equals + 1)..].Trim();
            }
        }

        return result;
    }

    /// <summary>Reads one fmtp parameter.</summary>
    /// <param name="parameters">The raw fmtp parameter string, or <see langword="null"/>.</param>
    /// <param name="key">Parameter name, compared ordinally.</param>
    /// <returns>The value, or <see langword="null"/> when the key is absent.</returns>
    public static string? GetValue(string? parameters, string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Parse(parameters).TryGetValue(key, out var value) ? value : null;
    }

    /// <summary>Tests whether an fmtp string contains <paramref name="key"/> with <paramref name="value"/>.</summary>
    /// <param name="parameters">The raw fmtp parameter string, or <see langword="null"/>.</param>
    /// <param name="key">Parameter name, compared ordinally.</param>
    /// <param name="value">Expected value, compared ordinally and case-insensitively.</param>
    /// <returns>True on an exact key match with an equal value.</returns>
    public static bool Matches(string? parameters, string key, string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var actual = GetValue(parameters, key);
        return actual is not null && string.Equals(actual, value, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Renders key/value pairs as <c>key=value;key=value</c> using no spaces, as Chrome does.</summary>
    /// <param name="parameters">The pairs, emitted in enumeration order.</param>
    /// <returns>The joined parameter string.</returns>
    public static string Format(IEnumerable<KeyValuePair<string, string>> parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        return string.Join(';', parameters.Select(static p =>
            p.Value.Length == 0 ? p.Key : p.Key + "=" + p.Value));
    }
}
