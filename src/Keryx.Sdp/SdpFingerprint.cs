namespace Keryx.Sdp;

/// <summary>
/// An <c>a=fingerprint</c> value: a hash algorithm name and the certificate digest rendered as
/// colon-separated uppercase hex.
/// </summary>
public sealed record SdpFingerprint
{
    /// <summary>Creates a fingerprint, normalising the digest to colon-separated uppercase hex.</summary>
    /// <param name="algorithm">Hash algorithm token, for example <c>sha-256</c>.</param>
    /// <param name="value">Digest, with or without colons, in either case.</param>
    public SdpFingerprint(string algorithm, string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm);
        ArgumentNullException.ThrowIfNull(value);
        Algorithm = algorithm;
        Value = value.Trim().ToUpperInvariant();
    }

    /// <summary>Hash algorithm token, for example <c>sha-256</c>.</summary>
    public string Algorithm { get; }

    /// <summary>Digest as colon-separated uppercase hex, for example <c>AB:CD:...</c>.</summary>
    public string Value { get; }

    /// <summary>Builds a fingerprint from raw digest bytes.</summary>
    /// <param name="algorithm">Hash algorithm token, for example <c>sha-256</c>.</param>
    /// <param name="hash">The digest bytes.</param>
    /// <returns>The fingerprint with a colon-separated uppercase hex value.</returns>
    public static SdpFingerprint FromHash(string algorithm, ReadOnlySpan<byte> hash)
    {
        var hex = Convert.ToHexString(hash);
        var builder = new System.Text.StringBuilder(hex.Length + (hex.Length / 2));
        for (var i = 0; i < hex.Length; i += 2)
        {
            if (i > 0)
            {
                builder.Append(':');
            }

            builder.Append(hex[i]).Append(hex[i + 1]);
        }

        return new SdpFingerprint(algorithm, builder.ToString());
    }

    /// <summary>Parses an <c>a=fingerprint</c> value of the form <c>&lt;algorithm&gt; &lt;digest&gt;</c>.</summary>
    /// <param name="value">The attribute value.</param>
    /// <param name="fingerprint">Receives the parsed fingerprint.</param>
    /// <returns>True when both fields are present.</returns>
    public static bool TryParse(string? value, out SdpFingerprint? fingerprint)
    {
        fingerprint = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var parts = value.Trim().Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2 || parts[1].Length == 0)
        {
            return false;
        }

        fingerprint = new SdpFingerprint(parts[0], parts[1]);
        return true;
    }

    /// <summary>Renders the value part of the <c>a=fingerprint</c> attribute.</summary>
    /// <returns>For example <c>sha-256 AB:CD:...</c>.</returns>
    public string ToAttributeValue() => Algorithm + " " + Value;

    /// <summary>Renders the complete attribute without a line terminator.</summary>
    /// <returns>For example <c>a=fingerprint:sha-256 AB:CD:...</c>.</returns>
    public override string ToString() => "a=fingerprint:" + ToAttributeValue();
}
