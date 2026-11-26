namespace Keryx.IntegrationTests;

/// <summary>
/// A minimal Ogg reader for the barge-in tone fixtures: it walks Ogg pages, reassembles packets from
/// the lacing values (a 255-byte segment continues the packet), drops the two Opus header packets and
/// returns the audio packets in order. Enough to feed one Opus packet per RTP packet to a sender.
/// </summary>
internal static class OggOpusReader
{
    private static readonly byte[] CapturePattern = "OggS"u8.ToArray();

    /// <summary>Reads the Opus audio packets from an Ogg Opus file.</summary>
    /// <param name="path">The file path.</param>
    /// <returns>The audio packets, with the <c>OpusHead</c> and <c>OpusTags</c> packets removed.</returns>
    internal static List<byte[]> ReadPackets(string path)
    {
        var data = File.ReadAllBytes(path);
        var packets = new List<byte[]>();
        using var current = new MemoryStream();

        var position = 0;
        while (position + 27 <= data.Length)
        {
            if (!data.AsSpan(position, 4).SequenceEqual(CapturePattern))
            {
                // Not an Ogg page boundary; stop rather than misparse garbage.
                break;
            }

            var segmentCount = data[position + 26];
            var tableStart = position + 27;
            var bodyStart = tableStart + segmentCount;
            if (bodyStart > data.Length)
            {
                break;
            }

            var offset = bodyStart;
            for (var segment = 0; segment < segmentCount; segment++)
            {
                var lacing = data[tableStart + segment];
                if (offset + lacing > data.Length)
                {
                    return AudioPackets(packets);
                }

                current.Write(data, offset, lacing);
                offset += lacing;

                if (lacing < 255)
                {
                    packets.Add(current.ToArray());
                    current.SetLength(0);
                }
            }

            position = offset;
        }

        return AudioPackets(packets);
    }

    private static List<byte[]> AudioPackets(List<byte[]> packets)
    {
        // OpusHead is packet 0 and OpusTags packet 1; everything after is audio.
        return packets.Count <= 2 ? [] : packets.GetRange(2, packets.Count - 2);
    }
}
