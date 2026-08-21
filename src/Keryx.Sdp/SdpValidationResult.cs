namespace Keryx.Sdp;

/// <summary>The outcome of checking an answer against the offer it responds to.</summary>
public sealed class SdpValidationResult
{
    private readonly List<string> _errors = [];

    /// <summary>True when no rule was violated.</summary>
    public bool IsValid => _errors.Count == 0;

    /// <summary>The violations found, in the order they were detected.</summary>
    public IReadOnlyList<string> Errors => _errors;

    /// <summary>Throws when the document is invalid.</summary>
    /// <exception cref="SdpException">At least one rule was violated.</exception>
    public void ThrowIfInvalid()
    {
        if (!IsValid)
        {
            throw new SdpException("Invalid SDP answer: " + string.Join("; ", _errors));
        }
    }

    /// <summary>A human-readable summary of the outcome.</summary>
    /// <returns><c>valid</c>, or the joined error list.</returns>
    public override string ToString() => IsValid ? "valid" : string.Join("; ", _errors);

    internal void Add(string error) => _errors.Add(error);
}
