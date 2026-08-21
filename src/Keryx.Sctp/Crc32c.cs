namespace Keryx.Sctp;

/// <summary>
/// Table-driven CRC-32C (Castagnoli) — the checksum SCTP puts in its common header (RFC 9260 §6.8).
/// </summary>
/// <remarks>
/// <para>
/// This is the standard reflected CRC-32 with the Castagnoli polynomial 0x1EDC6F41, whose reflected
/// form is 0x82F63B78. The register is seeded with 0xFFFFFFFF, input and output are reflected, and
/// the final register is complemented. The canonical check value for the ASCII string
/// <c>"123456789"</c> is <c>0xE3069283</c>.
/// </para>
/// <para>
/// Implemented by hand (a 256-entry nibble-free byte table) because Keryx takes no NuGet
/// dependencies; <c>System.IO.Hashing.Crc32</c>/<c>Crc32C</c> are out of bounds.
/// </para>
/// </remarks>
public static class Crc32c
{
    /// <summary>Reflected form of the Castagnoli polynomial 0x1EDC6F41.</summary>
    public const uint ReflectedPolynomial = 0x82F63B78u;

    /// <summary>Initial register value for a fresh computation.</summary>
    public const uint Seed = 0xFFFFFFFFu;

    private static readonly uint[] Table = BuildTable();

    /// <summary>Computes the complete CRC-32C of <paramref name="data"/>.</summary>
    /// <param name="data">Bytes to checksum.</param>
    /// <returns>The finalized (complemented) CRC-32C value.</returns>
    public static uint Compute(ReadOnlySpan<byte> data) => Finish(Update(Seed, data));

    /// <summary>
    /// Folds <paramref name="data"/> into a running, not-yet-finalized register so a checksum can be
    /// computed over several discontiguous spans (SCTP checksums the header with the checksum field
    /// treated as zero, which means three spans).
    /// </summary>
    /// <param name="state">Register value; start from <see cref="Seed"/>.</param>
    /// <param name="data">Bytes to fold in.</param>
    /// <returns>The updated register value.</returns>
    public static uint Update(uint state, ReadOnlySpan<byte> data)
    {
        var table = Table;
        foreach (var b in data)
        {
            state = table[(state ^ b) & 0xFF] ^ (state >> 8);
        }

        return state;
    }

    /// <summary>Finalizes a running register produced by <see cref="Update"/>.</summary>
    /// <param name="state">The running register value.</param>
    /// <returns>The finalized CRC-32C value.</returns>
    public static uint Finish(uint state) => ~state;

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            var entry = i;
            for (var bit = 0; bit < 8; bit++)
            {
                entry = (entry & 1) != 0 ? (entry >> 1) ^ ReflectedPolynomial : entry >> 1;
            }

            table[i] = entry;
        }

        return table;
    }
}
