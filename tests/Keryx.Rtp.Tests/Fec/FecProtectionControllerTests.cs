using FluentAssertions;
using Keryx.Rtp.Fec;
using Xunit;

namespace Keryx.Rtp.Tests.Fec;

/// <summary>
/// The adaptive FEC protection group size: a repair packet recovers one loss per group, so the group is
/// tightened immediately when reported loss rises and relaxed slowly and stepwise when the path calms.
/// Every case here drives the controller with a fixed sequence of reports, so nothing depends on time.
/// </summary>
public class FecProtectionControllerTests
{
    [Fact]
    public void Defaults_start_at_ten_with_no_loss()
    {
        var controller = new FecProtectionController();

        controller.GroupSize.Should().Be(FecProtectionOptions.DefaultInitialGroupSize);
        controller.SmoothedLoss.Should().Be(0);
        controller.OverheadFraction.Should().Be(1.0 / 11);
    }

    [Fact]
    public void Invalid_bounds_throw()
    {
        var minAboveInitial = new FecProtectionOptions { MinGroupSize = 11, InitialGroupSize = 10 };
        var initialAboveMax = new FecProtectionOptions { InitialGroupSize = 15, MaxGroupSize = 10 };
        var maxTooLarge = new FecProtectionOptions { MaxGroupSize = FecProtectionOptions.MaxSupportedGroupSize + 1 };
        var minBelowOne = new FecProtectionOptions { MinGroupSize = 0 };
        var relaxBelowOne = new FecProtectionOptions { RelaxAfterReports = 0 };

        var constructors = new Func<FecProtectionController>[]
        {
            () => new FecProtectionController(minAboveInitial),
            () => new FecProtectionController(initialAboveMax),
            () => new FecProtectionController(maxTooLarge),
            () => new FecProtectionController(minBelowOne),
            () => new FecProtectionController(relaxBelowOne),
        };

        foreach (var construct in constructors)
        {
            construct.Should().Throw<ArgumentOutOfRangeException>();
        }
    }

    [Fact]
    public void Tightens_immediately_on_a_single_loss_report()
    {
        var controller = new FecProtectionController();

        controller.OnReportedLoss(0.30).Should().BeTrue();
        controller.GroupSize.Should().Be(3);
        controller.OverheadFraction.Should().Be(0.25);
    }

    [Fact]
    public void NaN_is_ignored_and_out_of_range_values_clamp()
    {
        var controller = new FecProtectionController();

        controller.OnReportedLoss(double.NaN).Should().BeFalse();
        controller.SmoothedLoss.Should().Be(0);
        controller.GroupSize.Should().Be(10);

        // A negative sample clamps to zero: calm, so no tightening.
        controller.OnReportedLoss(-5).Should().BeFalse();
        controller.SmoothedLoss.Should().Be(0);
        controller.GroupSize.Should().Be(10);

        // A sample above one clamps to one: maximum loss, so maximum protection. A fresh controller makes
        // the clamped value the first sample, so the smoothed estimate is exactly one.
        var high = new FecProtectionController();
        high.OnReportedLoss(5).Should().BeTrue();
        high.SmoothedLoss.Should().Be(1);
        high.GroupSize.Should().Be(3);
    }

    [Fact]
    public void Relaxes_only_after_the_configured_run_of_calm_reports()
    {
        var controller = new FecProtectionController(); // RelaxAfterReports = 5

        for (var i = 0; i < 4; i++)
        {
            controller.OnReportedLoss(0.0).Should().BeFalse();
            controller.GroupSize.Should().Be(10);
        }

        controller.OnReportedLoss(0.0).Should().BeTrue("the fifth calm report buys one step");
        controller.GroupSize.Should().Be(15);
    }

    [Fact]
    public void Relaxation_never_skips_a_ladder_step()
    {
        var controller = new FecProtectionController();
        controller.OnReportedLoss(0.30).Should().BeTrue();
        controller.GroupSize.Should().Be(3);

        var changes = new List<(int ReportIndex, int GroupSize)>();
        for (var report = 0; report < 1_000; report++)
        {
            if (controller.OnReportedLoss(0.0))
            {
                changes.Add((report, controller.GroupSize));
            }
        }

        changes.Select(c => c.GroupSize).Should().ContainInOrder(4, 6, 10, 15);
        changes.Select(c => c.GroupSize).Should().OnlyHaveUniqueItems("a relaxation is one step at a time");
        changes.First().GroupSize.Should().Be(4, "the ladder starts at 3 and steps upward");

        for (var i = 1; i < changes.Count; i++)
        {
            (changes[i].ReportIndex - changes[i - 1].ReportIndex).Should().BeGreaterThanOrEqualTo(
                5,
                "each step needs a fresh run of calm reports");
        }
    }

    [Fact]
    public void A_path_hovering_on_a_threshold_does_not_flap()
    {
        var controller = new FecProtectionController();

        // Settle the controller around the 3% tier boundary.
        for (var i = 0; i < 200; i++)
        {
            controller.OnReportedLoss(i % 2 == 0 ? 0.028 : 0.032);
        }

        var changes = 0;
        for (var i = 0; i < 200; i++)
        {
            if (controller.OnReportedLoss(i % 2 == 0 ? 0.028 : 0.032))
            {
                changes++;
            }
        }

        changes.Should().Be(0, "the hysteresis band must keep a hovering path from oscillating");
    }

    [Fact]
    public void A_loss_spike_restarts_the_calm_count()
    {
        var controller = new FecProtectionController();

        for (var i = 0; i < 4; i++)
        {
            controller.OnReportedLoss(0.0).Should().BeFalse();
        }

        // The spike tightens the group and clears the partial calm run.
        controller.OnReportedLoss(0.30).Should().BeTrue();
        controller.GroupSize.Should().Be(3);

        var reportsSinceSpike = 0;
        while (!controller.OnReportedLoss(0.0))
        {
            reportsSinceSpike++;
            reportsSinceSpike.Should().BeLessThan(100, "the controller must eventually relax");
        }

        // The first relaxation has to be a full new run after the spike, not the remains of the old one.
        (reportsSinceSpike + 1).Should().BeGreaterThanOrEqualTo(5);
        controller.GroupSize.Should().Be(4);
    }

    [Fact]
    public void Disabling_adaptation_pins_the_group_but_still_tracks_loss()
    {
        var controller = new FecProtectionController(new FecProtectionOptions { AdaptiveGroupSize = false });

        foreach (var sample in new[] { 0.5, 0.0, 0.0, 0.2, 0.0, 1.0 })
        {
            controller.OnReportedLoss(sample).Should().BeFalse();
            controller.GroupSize.Should().Be(10);
        }

        controller.SmoothedLoss.Should().BeGreaterThan(0, "smoothing still runs with adaptation off");
    }

    [Fact]
    public void Configured_bounds_are_respected()
    {
        var controller = new FecProtectionController(new FecProtectionOptions
        {
            MinGroupSize = 5,
            MaxGroupSize = 12,
            InitialGroupSize = 10,
        });

        controller.OnReportedLoss(0.5).Should().BeTrue();
        controller.GroupSize.Should().Be(5);

        for (var i = 0; i < 1_000; i++)
        {
            controller.OnReportedLoss(0.0);
            controller.GroupSize.Should().BeLessThanOrEqualTo(12, "adaptation must never exceed MaxGroupSize");
        }

        controller.GroupSize.Should().Be(12);
    }

    [Fact]
    public void Mutating_the_options_after_construction_has_no_effect()
    {
        var options = new FecProtectionOptions();
        var controller = new FecProtectionController(options);

        options.MinGroupSize = 9;
        options.MaxGroupSize = 10;
        options.InitialGroupSize = 10;
        options.RelaxAfterReports = 1;
        options.AdaptiveGroupSize = false;

        controller.GroupSize.Should().Be(10);

        // The copied defaults (Min 3, Max 15) still govern: a heavy-loss report reaches the floor of 3,
        // which the mutated MinGroupSize of 9 would forbid.
        controller.OnReportedLoss(0.30).Should().BeTrue();
        controller.GroupSize.Should().Be(3);
    }
}
