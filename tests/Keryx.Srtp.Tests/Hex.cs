namespace Keryx.Srtp.Tests;

/// <summary>Hex helpers so RFC test vectors can be pasted verbatim, whitespace and all.</summary>
internal static class Hex
{
    public static byte[] Parse(string text)
    {
        Span<char> compact = text.Length <= 512 ? stackalloc char[text.Length] : new char[text.Length];
        var n = 0;
        foreach (var c in text)
        {
            if (!char.IsWhiteSpace(c))
            {
                compact[n++] = c;
            }
        }

        return Convert.FromHexString(compact[..n]);
    }

    public static string ToString(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes);
}
