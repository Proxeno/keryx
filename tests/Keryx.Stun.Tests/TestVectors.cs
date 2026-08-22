namespace Keryx.Stun.Tests;

/// <summary>Hex-dump helpers shared by the RFC 5769 vector tests.</summary>
internal static class Hex
{
    /// <summary>Parses a whitespace-separated hex dump into bytes.</summary>
    public static byte[] Parse(string dump)
    {
        var compact = new string([.. dump.Where(char.IsAsciiHexDigit)]);
        return Convert.FromHexString(compact);
    }
}
