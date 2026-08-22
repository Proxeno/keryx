namespace Keryx.Stun;

/// <summary>Tuning knobs for <see cref="StunClient"/>'s RFC 5389 section 7.2.1 retransmission schedule.</summary>
public sealed class StunClientOptions
{
    /// <summary>
    /// The initial retransmission timeout (RTO). Doubles after every unanswered transmission.
    /// RFC 5389 recommends 500 ms.
    /// </summary>
    public TimeSpan InitialRetransmissionTimeout { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// The total number of transmissions (Rc in RFC 5389). The default of 7 gives the RFC's
    /// 39.5 s budget with the default RTO; tests should lower it.
    /// </summary>
    public int MaxTransmissions { get; set; } = 7;

    /// <summary>
    /// How many RTOs to wait after the final transmission before declaring failure (Rm in
    /// RFC 5389 section 7.2.1). The RFC value is 16.
    /// </summary>
    public int FinalWaitMultiplier { get; set; } = 16;

    /// <summary>A SOFTWARE attribute to advertise, or null to send none.</summary>
    public string? Software { get; set; }

    /// <summary>Whether to append a FINGERPRINT attribute to outgoing requests.</summary>
    public bool AddFingerprint { get; set; } = true;

    /// <summary>Whether to drop responses whose FINGERPRINT attribute is present but wrong.</summary>
    public bool RequireValidFingerprint { get; set; } = true;

    internal StunClientOptions Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxTransmissions, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(FinalWaitMultiplier, 1);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(InitialRetransmissionTimeout, TimeSpan.Zero);
        return this;
    }
}
