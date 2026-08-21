namespace Keryx.Sdp;

/// <summary>
/// Lines that a session description and a media description have in common: optional connection
/// data, bandwidth lines, and the ordered attribute list. Attribute order is preserved exactly as
/// parsed so that a parse/serialize round trip is lossless.
/// </summary>
public abstract class SdpSection
{
    /// <summary>Creates an empty section.</summary>
    protected SdpSection()
    {
    }

    /// <summary>Optional <c>c=</c> connection data for this section.</summary>
    public SdpConnection? Connection { get; set; }

    /// <summary>Raw <c>b=</c> values (the text after <c>b=</c>), in document order.</summary>
    public IList<string> Bandwidths { get; } = new List<string>();

    /// <summary>The <c>a=</c> attributes of this section, in document order.</summary>
    /// <remarks>
    /// Attributes Keryx does not model are kept here verbatim, which is what makes the round trip
    /// lossless. Mutate this list directly for anything the typed accessors do not cover.
    /// </remarks>
    public IList<SdpAttribute> Attributes { get; } = new List<SdpAttribute>();

    /// <summary>
    /// Complete lines whose type this model does not interpret, preserved verbatim (including the
    /// <c>x=</c> prefix) and re-emitted at the end of the section.
    /// </summary>
    public IList<string> UnknownLines { get; } = new List<string>();

    /// <summary>The first attribute named <paramref name="name"/>, or <see langword="null"/>.</summary>
    /// <param name="name">Attribute name, compared ordinally.</param>
    /// <returns>The attribute, or <see langword="null"/> when absent.</returns>
    public SdpAttribute? FindAttribute(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        foreach (var attribute in Attributes)
        {
            if (string.Equals(attribute.Name, name, StringComparison.Ordinal))
            {
                return attribute;
            }
        }

        return null;
    }

    /// <summary>Every attribute named <paramref name="name"/>, in document order.</summary>
    /// <param name="name">Attribute name, compared ordinally.</param>
    /// <returns>The matching attributes.</returns>
    public IEnumerable<SdpAttribute> FindAttributes(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return Attributes.Where(a => string.Equals(a.Name, name, StringComparison.Ordinal));
    }

    /// <summary>The value of the first attribute named <paramref name="name"/>.</summary>
    /// <param name="name">Attribute name, compared ordinally.</param>
    /// <returns>The raw value, or <see langword="null"/> when the attribute is absent or a flag.</returns>
    public string? GetAttributeValue(string name) => FindAttribute(name)?.Value;

    /// <summary>The values of every attribute named <paramref name="name"/>, skipping flags.</summary>
    /// <param name="name">Attribute name, compared ordinally.</param>
    /// <returns>The raw values, in document order.</returns>
    public IEnumerable<string> GetAttributeValues(string name) =>
        FindAttributes(name).Select(static a => a.Value).OfType<string>();

    /// <summary>True when at least one attribute named <paramref name="name"/> is present.</summary>
    /// <param name="name">Attribute name, compared ordinally.</param>
    /// <returns>True when present, in flag or value form.</returns>
    public bool HasAttribute(string name) => FindAttribute(name) is not null;

    /// <summary>Appends an attribute, keeping any existing attribute with the same name.</summary>
    /// <param name="name">Attribute name.</param>
    /// <param name="value">Attribute value, or <see langword="null"/> for a flag.</param>
    public void AddAttribute(string name, string? value = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        Attributes.Add(new SdpAttribute(name, value));
    }

    /// <summary>
    /// Replaces the first attribute named <paramref name="name"/> in place, drops any duplicates and
    /// appends the attribute when it was absent.
    /// </summary>
    /// <param name="name">Attribute name.</param>
    /// <param name="value">Attribute value, or <see langword="null"/> for a flag.</param>
    public void SetAttribute(string name, string? value = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        var first = -1;
        for (var i = Attributes.Count - 1; i >= 0; i--)
        {
            if (!string.Equals(Attributes[i].Name, name, StringComparison.Ordinal))
            {
                continue;
            }

            if (first >= 0)
            {
                Attributes.RemoveAt(first);
            }

            first = i;
        }

        if (first >= 0)
        {
            Attributes[first] = new SdpAttribute(name, value);
        }
        else
        {
            Attributes.Add(new SdpAttribute(name, value));
        }
    }

    /// <summary>Removes every attribute named <paramref name="name"/>.</summary>
    /// <param name="name">Attribute name.</param>
    /// <returns>The number of attributes removed.</returns>
    public int RemoveAttributes(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        var removed = 0;
        for (var i = Attributes.Count - 1; i >= 0; i--)
        {
            if (string.Equals(Attributes[i].Name, name, StringComparison.Ordinal))
            {
                Attributes.RemoveAt(i);
                removed++;
            }
        }

        return removed;
    }

    /// <summary>Adds or removes a valueless attribute such as <c>a=rtcp-mux</c>.</summary>
    /// <param name="name">Attribute name.</param>
    /// <param name="present">True to ensure the flag is present, false to remove it.</param>
    public void SetFlag(string name, bool present)
    {
        if (present)
        {
            SetAttribute(name, null);
        }
        else
        {
            RemoveAttributes(name);
        }
    }

    /// <summary><c>a=ice-ufrag</c>. Setting <see langword="null"/> removes the attribute.</summary>
    public string? IceUfrag
    {
        get => GetAttributeValue(SdpAttributeNames.IceUfrag);
        set => SetOrRemove(SdpAttributeNames.IceUfrag, value);
    }

    /// <summary><c>a=ice-pwd</c>. Setting <see langword="null"/> removes the attribute.</summary>
    public string? IcePwd
    {
        get => GetAttributeValue(SdpAttributeNames.IcePwd);
        set => SetOrRemove(SdpAttributeNames.IcePwd, value);
    }

    /// <summary>The space-separated tokens of <c>a=ice-options</c>, for example <c>trickle</c>.</summary>
    /// <returns>The tokens, or an empty list when the attribute is absent.</returns>
    public IReadOnlyList<string> GetIceOptions()
    {
        var value = GetAttributeValue(SdpAttributeNames.IceOptions);
        return string.IsNullOrWhiteSpace(value)
            ? []
            : value.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>Writes <c>a=ice-options</c>. Passing no options removes the attribute.</summary>
    /// <param name="options">ICE option tokens, for example <c>trickle</c>.</param>
    public void SetIceOptions(params string[] options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Length == 0)
        {
            RemoveAttributes(SdpAttributeNames.IceOptions);
            return;
        }

        SetAttribute(SdpAttributeNames.IceOptions, string.Join(' ', options));
    }

    /// <summary>True when <c>a=ice-options</c> lists the <c>trickle</c> token.</summary>
    public bool SupportsTrickleIce => GetIceOptions().Contains("trickle", StringComparer.Ordinal);

    /// <summary>
    /// The first well-formed <c>a=fingerprint</c>. Setting <see langword="null"/> removes every
    /// fingerprint attribute.
    /// </summary>
    public SdpFingerprint? Fingerprint
    {
        get => GetFingerprints().FirstOrDefault();
        set
        {
            if (value is null)
            {
                RemoveAttributes(SdpAttributeNames.Fingerprint);
            }
            else
            {
                SetAttribute(SdpAttributeNames.Fingerprint, value.ToAttributeValue());
            }
        }
    }

    /// <summary>Every well-formed <c>a=fingerprint</c>, in document order.</summary>
    /// <returns>The fingerprints; malformed values are skipped.</returns>
    public IReadOnlyList<SdpFingerprint> GetFingerprints()
    {
        var result = new List<SdpFingerprint>();
        foreach (var value in GetAttributeValues(SdpAttributeNames.Fingerprint))
        {
            if (SdpFingerprint.TryParse(value, out var fingerprint) && fingerprint is not null)
            {
                result.Add(fingerprint);
            }
        }

        return result;
    }

    /// <summary><c>a=setup</c>. Setting <see langword="null"/> removes the attribute.</summary>
    public SdpSetupRole? Setup
    {
        get => SdpSetup.TryParse(GetAttributeValue(SdpAttributeNames.Setup), out var role) ? role : null;
        set
        {
            if (value is null)
            {
                RemoveAttributes(SdpAttributeNames.Setup);
            }
            else
            {
                SetAttribute(SdpAttributeNames.Setup, value.Value.ToAttributeValue());
            }
        }
    }

    private protected void SetOrRemove(string name, string? value)
    {
        if (value is null)
        {
            RemoveAttributes(name);
        }
        else
        {
            SetAttribute(name, value);
        }
    }
}
