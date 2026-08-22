using System.Globalization;
using System.Text;

namespace Keryx.Sdp;

/// <summary>Serializes a <see cref="SessionDescription"/> in RFC 4566 line order, always CRLF terminated.</summary>
internal static class SdpWriter
{
    internal static string Write(SessionDescription session)
    {
        ArgumentNullException.ThrowIfNull(session);
        var builder = new StringBuilder(1024);

        Line(builder, 'v', session.Version.ToString(CultureInfo.InvariantCulture));
        Line(builder, 'o', session.Origin.ToLineValue());
        Line(builder, 's', session.SessionName);
        LineIf(builder, 'i', session.Information);
        LineIf(builder, 'u', session.Uri);
        foreach (var email in session.Emails)
        {
            Line(builder, 'e', email);
        }

        foreach (var phone in session.PhoneNumbers)
        {
            Line(builder, 'p', phone);
        }

        if (session.Connection is { } connection)
        {
            Line(builder, 'c', connection.ToLineValue());
        }

        foreach (var bandwidth in session.Bandwidths)
        {
            Line(builder, 'b', bandwidth);
        }

        if (session.Timings.Count == 0)
        {
            Line(builder, 't', "0 0");
        }
        else
        {
            foreach (var timing in session.Timings)
            {
                Line(builder, 't', timing.ToLineValue());
                foreach (var repeat in timing.RepeatTimes)
                {
                    Line(builder, 'r', repeat);
                }
            }
        }

        LineIf(builder, 'z', session.TimeZoneAdjustments);
        LineIf(builder, 'k', session.EncryptionKey);
        WriteAttributes(builder, session);

        foreach (var media in session.MediaDescriptions)
        {
            WriteMedia(builder, media);
        }

        return builder.ToString();
    }

    internal static string WriteMedia(MediaDescription media)
    {
        ArgumentNullException.ThrowIfNull(media);
        var builder = new StringBuilder(256);
        WriteMedia(builder, media);
        return builder.ToString();
    }

    private static void WriteMedia(StringBuilder builder, MediaDescription media)
    {
        Line(builder, 'm', media.ToMediaLineValue());
        LineIf(builder, 'i', media.Information);
        if (media.Connection is { } connection)
        {
            Line(builder, 'c', connection.ToLineValue());
        }

        foreach (var bandwidth in media.Bandwidths)
        {
            Line(builder, 'b', bandwidth);
        }

        LineIf(builder, 'k', media.EncryptionKey);
        WriteAttributes(builder, media);
    }

    private static void WriteAttributes(StringBuilder builder, SdpSection section)
    {
        foreach (var attribute in section.Attributes)
        {
            Line(builder, 'a', attribute.ToAttributeValue());
        }

        foreach (var unknown in section.UnknownLines)
        {
            builder.Append(unknown).Append(SessionDescription.LineTerminator);
        }
    }

    private static void Line(StringBuilder builder, char type, string value) =>
        builder.Append(type).Append('=').Append(value).Append(SessionDescription.LineTerminator);

    private static void LineIf(StringBuilder builder, char type, string? value)
    {
        if (value is not null)
        {
            Line(builder, type, value);
        }
    }
}
