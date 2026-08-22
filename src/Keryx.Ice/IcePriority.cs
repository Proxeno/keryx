namespace Keryx.Ice;

/// <summary>
/// The candidate and candidate-pair priority formulas of RFC 8445 sections 5.1.2.1 and 6.1.2.3.
/// </summary>
public static class IcePriority
{
    /// <summary>Recommended type preference for host candidates (RFC 8445 section 5.1.2.2).</summary>
    public const int HostTypePreference = 126;

    /// <summary>Recommended type preference for peer-reflexive candidates.</summary>
    public const int PeerReflexiveTypePreference = 110;

    /// <summary>Recommended type preference for server-reflexive candidates.</summary>
    public const int ServerReflexiveTypePreference = 100;

    /// <summary>Recommended type preference for relayed candidates.</summary>
    public const int RelayedTypePreference = 0;

    /// <summary>The highest local preference, used when an agent has a single usable interface.</summary>
    public const int MaxLocalPreference = 65535;

    /// <summary>The recommended type preference for <paramref name="type"/>.</summary>
    /// <param name="type">The candidate type.</param>
    public static int TypePreference(IceCandidateType type) => type switch
    {
        IceCandidateType.Host => HostTypePreference,
        IceCandidateType.PeerReflexive => PeerReflexiveTypePreference,
        IceCandidateType.ServerReflexive => ServerReflexiveTypePreference,
        IceCandidateType.Relayed => RelayedTypePreference,
        _ => 0,
    };

    /// <summary>
    /// Candidate priority: <c>2^24 * type-preference + 2^8 * local-preference + (256 - component)</c>
    /// (RFC 8445 section 5.1.2.1).
    /// </summary>
    /// <param name="type">The candidate type, which selects the type preference.</param>
    /// <param name="localPreference">0-65535; higher means a more preferred interface.</param>
    /// <param name="component">The component id; 1 for a bundled, rtcp-muxed WebRTC session.</param>
    public static uint Compute(IceCandidateType type, int localPreference = MaxLocalPreference, int component = 1)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(localPreference);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(localPreference, MaxLocalPreference);
        ArgumentOutOfRangeException.ThrowIfLessThan(component, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(component, 256);

        return ((uint)TypePreference(type) << 24) | ((uint)localPreference << 8) | (uint)(256 - component);
    }

    /// <summary>
    /// Candidate-pair priority:
    /// <c>2^32 * MIN(G, D) + 2 * MAX(G, D) + (G &gt; D ? 1 : 0)</c>, where G is the controlling
    /// agent's candidate priority and D the controlled agent's (RFC 8445 section 6.1.2.3).
    /// </summary>
    /// <param name="controllingPriority">The controlling agent's candidate priority (G).</param>
    /// <param name="controlledPriority">The controlled agent's candidate priority (D).</param>
    public static ulong ComputePair(uint controllingPriority, uint controlledPriority)
    {
        var min = (ulong)Math.Min(controllingPriority, controlledPriority);
        var max = (ulong)Math.Max(controllingPriority, controlledPriority);
        return (min << 32) + (2 * max) + (controllingPriority > controlledPriority ? 1ul : 0ul);
    }
}
