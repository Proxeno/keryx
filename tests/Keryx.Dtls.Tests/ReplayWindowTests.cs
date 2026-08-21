using FluentAssertions;
using Xunit;

namespace Keryx.Dtls.Tests;

public class ReplayWindowTests
{
    [Fact]
    public void Accepts_a_monotonic_sequence()
    {
        var window = new ReplayWindow();

        for (ulong i = 0; i < 200; i++)
        {
            window.Accept(i).Should().BeTrue();
        }

        window.Highest.Should().Be(199);
    }

    [Fact]
    public void Rejects_an_exact_duplicate()
    {
        var window = new ReplayWindow();

        window.Accept(0).Should().BeTrue();
        window.Accept(0).Should().BeFalse();
        window.IsReplay(0).Should().BeTrue();
    }

    [Fact]
    public void Accepts_out_of_order_records_inside_the_window_once_each()
    {
        var window = new ReplayWindow();

        window.Accept(10).Should().BeTrue();
        window.Accept(5).Should().BeTrue();
        window.Accept(7).Should().BeTrue();
        window.Accept(5).Should().BeFalse();
        window.Accept(7).Should().BeFalse();
        window.Accept(6).Should().BeTrue();
        window.Highest.Should().Be(10);
    }

    [Fact]
    public void Rejects_records_that_fell_off_the_left_edge()
    {
        var window = new ReplayWindow();
        window.Accept(0).Should().BeTrue();
        window.Accept(ReplayWindow.WindowSize + 10).Should().BeTrue();

        window.IsReplay(0).Should().BeTrue();
        window.Accept(1).Should().BeFalse("sequence 1 is more than 64 behind the window's right edge");
        window.Accept(ReplayWindow.WindowSize + 10 - 63).Should().BeTrue("the oldest in-window slot is still usable");
    }

    [Fact]
    public void A_large_jump_forward_clears_the_bitmap()
    {
        var window = new ReplayWindow();
        for (ulong i = 0; i < 64; i++)
        {
            window.Accept(i).Should().BeTrue();
        }

        window.Accept(10_000).Should().BeTrue();
        window.Accept(10_000).Should().BeFalse();
        window.Accept(9_999).Should().BeTrue();
        window.Accept(9_940).Should().BeTrue();
        window.Accept(9_930).Should().BeFalse("that slot is outside the 64-entry window");
    }

    [Fact]
    public void The_first_record_may_have_any_sequence_number()
    {
        var window = new ReplayWindow();

        window.IsReplay(0).Should().BeFalse();
        window.Accept(123_456).Should().BeTrue();
        window.Highest.Should().Be(123_456);
    }

    [Fact]
    public void Rejecting_does_not_advance_the_window()
    {
        var window = new ReplayWindow();
        window.Accept(50).Should().BeTrue();

        window.Accept(50).Should().BeFalse();

        window.Highest.Should().Be(50);
        window.Accept(51).Should().BeTrue();
    }
}
