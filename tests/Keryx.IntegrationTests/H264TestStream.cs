using Keryx.Rtp.Packetization;

namespace Keryx.IntegrationTests;

/// <summary>
/// Reads the checked-in Annex B test pattern and groups its NAL units into access units, the way an
/// encoder hands frames to a sender.
/// </summary>
internal static class H264TestStream
{
    /// <summary>The repository-relative path of the encoded test pattern.</summary>
    internal static string AssetPath =>
        Path.Combine(AppContext.BaseDirectory, "assets", "test-pattern-640x360.h264");

    /// <summary>
    /// Splits the asset into access units. Every NAL unit is prefixed with a four-byte start code so
    /// the result is byte-comparable with what <see cref="H264Depacketizer"/> reconstructs, and a
    /// coded slice (NAL type 1 or 5) terminates the access unit it belongs to.
    /// </summary>
    /// <param name="maxAccessUnits">Stop after this many access units.</param>
    /// <returns>The access units, in decode order.</returns>
    internal static List<byte[]> ReadAccessUnits(int maxAccessUnits)
    {
        var data = File.ReadAllBytes(AssetPath);
        var accessUnits = new List<byte[]>(maxAccessUnits);
        var current = new List<byte>(64 * 1024);

        foreach (var nal in AnnexB.EnumerateNalUnits(data))
        {
            if (nal.Length == 0)
            {
                continue;
            }

            current.AddRange(AnnexB.FourByteStartCode);
            current.AddRange(nal);

            var type = (byte)(nal[0] & 0x1F);
            if (type is not (H264NalUnitType.NonIdrSlice or H264NalUnitType.IdrSlice))
            {
                continue;
            }

            accessUnits.Add([.. current]);
            current.Clear();
            if (accessUnits.Count == maxAccessUnits)
            {
                break;
            }
        }

        return accessUnits;
    }
}
