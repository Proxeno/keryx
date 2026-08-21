namespace Keryx.Srtp;

/// <summary>
/// The 32-bit word appended to every SRTCP packet: a one-bit <c>E</c> flag followed by the 31-bit
/// SRTCP index (RFC 3711 Section 3.4).
/// </summary>
internal static class SrtcpIndexWord
{
    /// <summary>Mask of the 31 index bits.</summary>
    public const uint IndexMask = 0x7FFF_FFFF;

    /// <summary>Mask of the encryption flag.</summary>
    public const uint EncryptedFlag = 0x8000_0000;

    /// <summary>Combines an index and the E flag into the wire word.</summary>
    public static uint Encode(uint index, bool encrypted) =>
        (index & IndexMask) | (encrypted ? EncryptedFlag : 0u);

    /// <summary>Extracts the 31-bit index.</summary>
    public static uint Index(uint word) => word & IndexMask;

    /// <summary>Extracts the E flag.</summary>
    public static bool IsEncrypted(uint word) => (word & EncryptedFlag) != 0;
}
