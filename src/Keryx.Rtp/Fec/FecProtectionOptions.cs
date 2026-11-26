namespace Keryx.Rtp.Fec;

/// <summary>
/// Tuning for how many media packets one forward-error-correction repair packet protects, and whether
/// that number adapts to the loss the receiver reports. See <see cref="FecProtectionController"/>.
/// </summary>
public sealed class FecProtectionOptions
{
    /// <summary>The default (and initial) protection group size.</summary>
    public const int DefaultInitialGroupSize = 10;

    /// <summary>
    /// The largest supported group size: the ULPFEC short mask spans 16 and the FlexFEC short mask 15
    /// sequence numbers, so a group of up to 15 always fits one repair packet's mask.
    /// </summary>
    public const int MaxSupportedGroupSize = 15;

    /// <summary>
    /// When true (the default) the group size follows the reported loss; when false the group stays at
    /// <see cref="InitialGroupSize"/> for the life of the connection.
    /// </summary>
    public bool AdaptiveGroupSize { get; set; } = true;

    /// <summary>The group size a connection starts with. Defaults to <see cref="DefaultInitialGroupSize"/>.</summary>
    public int InitialGroupSize { get; set; } = DefaultInitialGroupSize;

    /// <summary>The smallest (most protective) group size adaptation may choose. Defaults to 3.</summary>
    public int MinGroupSize { get; set; } = 3;

    /// <summary>The largest (cheapest) group size adaptation may choose. Defaults to <see cref="MaxSupportedGroupSize"/>.</summary>
    public int MaxGroupSize { get; set; } = MaxSupportedGroupSize;

    /// <summary>
    /// How many consecutive calm loss reports must be seen before the group relaxes by one step.
    /// Defaults to 5. Counts reports, not time.
    /// </summary>
    public int RelaxAfterReports { get; set; } = 5;
}
