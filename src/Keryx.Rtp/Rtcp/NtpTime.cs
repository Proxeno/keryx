namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Conversions between wall-clock time and the 64-bit NTP timestamp format carried by RTCP sender
/// reports (RFC 3550 §4).
/// </summary>
/// <remarks>
/// The format is a 32-bit count of seconds since 1 January 1900 00:00:00 UTC in the high half and a
/// 32-bit binary fraction of a second in the low half. Only the middle 32 bits (low 16 of the seconds,
/// high 16 of the fraction) are echoed in report blocks as LSR; see <see cref="ToCompact"/>.
/// </remarks>
public static class NtpTime
{
    /// <summary>Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).</summary>
    public const uint UnixEpochOffsetSeconds = 2_208_988_800;

    /// <summary>Converts Unix time in seconds-and-fraction form to a 64-bit NTP timestamp.</summary>
    /// <param name="unixSeconds">Whole seconds since the Unix epoch.</param>
    /// <param name="fraction">Fraction of a second in the range [0, 1).</param>
    /// <returns>The NTP timestamp.</returns>
    public static ulong FromUnixSeconds(long unixSeconds, double fraction)
    {
        var seconds = (ulong)(unixSeconds + UnixEpochOffsetSeconds);
        var frac = (ulong)(fraction * 4_294_967_296d);
        return (seconds << 32) | (frac & 0xFFFFFFFF);
    }

    /// <summary>Converts Unix time in milliseconds to a 64-bit NTP timestamp.</summary>
    /// <param name="unixMilliseconds">Milliseconds since the Unix epoch.</param>
    /// <returns>The NTP timestamp.</returns>
    public static ulong FromUnixMilliseconds(long unixMilliseconds)
    {
        var seconds = Math.DivRem(unixMilliseconds, 1000, out var remainder);
        if (remainder < 0)
        {
            seconds--;
            remainder += 1000;
        }

        return FromUnixSeconds(seconds, remainder / 1000d);
    }

    /// <summary>Converts a point in time to a 64-bit NTP timestamp.</summary>
    /// <param name="value">The instant to convert.</param>
    /// <returns>The NTP timestamp.</returns>
    public static ulong FromDateTimeOffset(DateTimeOffset value) =>
        FromUnixMilliseconds(value.ToUnixTimeMilliseconds());

    /// <summary>Converts a 64-bit NTP timestamp to milliseconds since the Unix epoch.</summary>
    /// <param name="ntpTimestamp">The NTP timestamp.</param>
    /// <returns>Milliseconds since the Unix epoch.</returns>
    public static long ToUnixMilliseconds(ulong ntpTimestamp)
    {
        var seconds = (long)(ntpTimestamp >> 32) - UnixEpochOffsetSeconds;
        var fraction = (double)(uint)ntpTimestamp / 4_294_967_296d;
        return (seconds * 1000) + (long)Math.Round(fraction * 1000d);
    }

    /// <summary>Converts a 64-bit NTP timestamp to a UTC point in time.</summary>
    /// <param name="ntpTimestamp">The NTP timestamp.</param>
    /// <returns>The corresponding instant, in UTC.</returns>
    public static DateTimeOffset ToDateTimeOffset(ulong ntpTimestamp) =>
        DateTimeOffset.FromUnixTimeMilliseconds(ToUnixMilliseconds(ntpTimestamp));

    /// <summary>
    /// Extracts the middle 32 bits of an NTP timestamp — the compact form echoed as the "last SR"
    /// field of a report block (RFC 3550 §6.4.1).
    /// </summary>
    /// <param name="ntpTimestamp">The full 64-bit NTP timestamp.</param>
    /// <returns>The 16.16 fixed-point compact timestamp.</returns>
    public static uint ToCompact(ulong ntpTimestamp) => (uint)((ntpTimestamp >> 16) & 0xFFFFFFFF);

    /// <summary>
    /// Converts a duration to the 16.16 fixed-point seconds representation used by the DLSR field
    /// (RFC 3550 §6.4.1).
    /// </summary>
    /// <param name="value">The delay to encode.</param>
    /// <returns>The delay in units of 1/65536 second, saturated at <see cref="uint.MaxValue"/>.</returns>
    public static uint ToFixed16(TimeSpan value)
    {
        var units = value.TotalSeconds * 65536d;
        if (units <= 0)
        {
            return 0;
        }

        return units >= uint.MaxValue ? uint.MaxValue : (uint)units;
    }

    /// <summary>Converts a 16.16 fixed-point seconds value (such as DLSR) back to a duration.</summary>
    /// <param name="value">The delay in units of 1/65536 second.</param>
    /// <returns>The delay.</returns>
    public static TimeSpan FromFixed16(uint value) => TimeSpan.FromSeconds(value / 65536d);
}
