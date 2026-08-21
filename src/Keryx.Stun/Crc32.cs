namespace Keryx.Stun;

/// <summary>
/// CRC-32 as used by the STUN FINGERPRINT attribute: the ITU-T V.42 / IEEE 802.3 polynomial
/// (reflected 0xEDB88320) with an all-ones initial value and a final complement.
/// </summary>
internal static class Crc32
{
    private static readonly uint[] Table = BuildTable();

    internal static uint Compute(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var b in data)
        {
            crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
        }

        return crc ^ 0xFFFFFFFFu;
    }

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (var i = 0u; i < 256u; i++)
        {
            var entry = i;
            for (var bit = 0; bit < 8; bit++)
            {
                entry = (entry & 1) != 0 ? 0xEDB88320u ^ (entry >> 1) : entry >> 1;
            }

            table[i] = entry;
        }

        return table;
    }
}
