using System.Globalization;
using Keryx.Core;

namespace Keryx.Sdp;

/// <summary>
/// Tolerant SDP reader. Anything malformed is skipped rather than rejected: a browser that adds a
/// line Keryx has never seen must not break the session.
/// </summary>
internal static class SdpParser
{
    internal static SessionDescription Parse(string text, IKeryxLogger? logger)
    {
        ArgumentNullException.ThrowIfNull(text);

        var session = new SessionDescription();
        MediaDescription? media = null;
        SdpTiming? timing = null;

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            if (line.Length == 0)
            {
                continue;
            }

            if (line.Length < 2 || line[1] != '=')
            {
                Skip(logger, line, "not a <type>=<value> line");
                continue;
            }

            var type = line[0];
            var value = line[2..];
            SdpSection section = media ?? (SdpSection)session;

            switch (type)
            {
                case 'v':
                    session.Version = int.TryParse(value.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var version)
                        ? version
                        : 0;
                    break;
                case 'o':
                    session.Origin = SdpOrigin.Parse(value);
                    break;
                case 's':
                    session.SessionName = value;
                    break;
                case 'i':
                    if (media is null)
                    {
                        session.Information = value;
                    }
                    else
                    {
                        media.Information = value;
                    }

                    break;
                case 'u':
                    session.Uri = value;
                    break;
                case 'e':
                    session.Emails.Add(value);
                    break;
                case 'p':
                    session.PhoneNumbers.Add(value);
                    break;
                case 'c':
                    section.Connection = SdpConnection.Parse(value);
                    break;
                case 'b':
                    section.Bandwidths.Add(value);
                    break;
                case 't':
                    timing = ParseTiming(value);
                    session.Timings.Add(timing);
                    break;
                case 'r':
                    if (timing is null)
                    {
                        Skip(logger, line, "r= line before any t= line");
                    }
                    else
                    {
                        timing.RepeatTimes.Add(value);
                    }

                    break;
                case 'z':
                    session.TimeZoneAdjustments = value;
                    break;
                case 'k':
                    if (media is null)
                    {
                        session.EncryptionKey = value;
                    }
                    else
                    {
                        media.EncryptionKey = value;
                    }

                    break;
                case 'a':
                    section.Attributes.Add(SdpAttribute.Parse(value));
                    break;
                case 'm':
                    media = ParseMediaLine(value);
                    session.MediaDescriptions.Add(media);
                    break;
                default:
                    Skip(logger, line, "unknown line type");
                    section.UnknownLines.Add(line);
                    break;
            }
        }

        return session;
    }

    private static SdpTiming ParseTiming(string value)
    {
        var fields = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return new SdpTiming(
            fields.Length > 0 ? fields[0] : "0",
            fields.Length > 1 ? fields[1] : "0");
    }

    private static MediaDescription ParseMediaLine(string value)
    {
        var fields = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var media = new MediaDescription
        {
            Media = fields.Length > 0 ? fields[0] : "application",
            Protocol = fields.Length > 2 ? fields[2] : "UDP/TLS/RTP/SAVPF",
        };

        if (fields.Length > 1)
        {
            var portField = fields[1];
            var slash = portField.IndexOf('/');
            if (slash >= 0)
            {
                if (int.TryParse(portField.AsSpan(slash + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var count))
                {
                    media.PortCount = count;
                }

                portField = portField[..slash];
            }

            media.Port = int.TryParse(portField, NumberStyles.None, CultureInfo.InvariantCulture, out var port)
                ? port
                : 0;
        }

        for (var i = 3; i < fields.Length; i++)
        {
            media.Formats.Add(fields[i]);
        }

        return media;
    }

    private static void Skip(IKeryxLogger? logger, string line, string reason)
    {
        if (logger?.IsEnabled(KeryxLogLevel.Debug) == true)
        {
            logger.Log(KeryxLogLevel.Debug, $"sdp: skipping line ({reason}): {line}");
        }
    }
}
