using FluentAssertions;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.Rtcp;

/// <summary>Coverage for the NTP timestamp conversions of RFC 3550 §4 and §6.4.1.</summary>
public class NtpTimeTests
{
    [Fact]
    public void Unix_epoch_maps_to_the_ntp_seconds_offset()
    {
        // RFC 3550 §4: NTP time is seconds since 1900-01-01, which is 2 208 988 800 s before 1970-01-01.
        NtpTime.FromDateTimeOffset(DateTimeOffset.UnixEpoch)
            .Should().Be((ulong)NtpTime.UnixEpochOffsetSeconds << 32);
    }

    [Fact]
    public void Round_trips_a_wall_clock_instant_to_millisecond_accuracy()
    {
        var instant = new DateTimeOffset(2026, 8, 21, 9, 42, 17, 456, TimeSpan.Zero);
        var ntp = NtpTime.FromDateTimeOffset(instant);
        NtpTime.ToDateTimeOffset(ntp).Should().Be(instant);
    }

    [Fact]
    public void Encodes_the_fractional_second_in_the_low_half()
    {
        var half = NtpTime.FromUnixSeconds(0, 0.5);
        (half & 0xFFFFFFFF).Should().Be(0x80000000);
    }

    [Fact]
    public void Compact_form_is_the_middle_thirty_two_bits()
    {
        // RFC 3550 §6.4.1: LSR is "the middle 32 bits out of 64 in the NTP timestamp".
        NtpTime.ToCompact(0x1122334455667788).Should().Be(0x33445566);
    }

    [Fact]
    public void Fixed16_encodes_delays_in_units_of_one_sixty_five_thousand_five_hundred_and_thirty_sixth_of_a_second()
    {
        // RFC 3550 §6.4.1: DLSR is expressed in units of 1/65536 seconds.
        NtpTime.ToFixed16(TimeSpan.FromSeconds(1)).Should().Be(65536);
        NtpTime.ToFixed16(TimeSpan.FromSeconds(0.5)).Should().Be(32768);
        NtpTime.FromFixed16(32768).Should().Be(TimeSpan.FromSeconds(0.5));
    }

    [Fact]
    public void Handles_times_before_the_unix_epoch()
    {
        var instant = DateTimeOffset.UnixEpoch.AddMilliseconds(-1500);
        NtpTime.ToDateTimeOffset(NtpTime.FromDateTimeOffset(instant)).Should().Be(instant);
    }
}
