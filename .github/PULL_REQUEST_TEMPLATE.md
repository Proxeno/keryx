<!--
Thanks for contributing to Keryx! Please read CONTRIBUTING.md first.
Keep PRs focused; unrelated changes are easier to review split apart.
-->

## Summary

<!-- What does this change and why? -->

## Related issues

<!-- e.g. Closes #123 -->

## Checklist

- [ ] `dotnet build Keryx.slnx` and `dotnet test Keryx.slnx` pass locally (see CONTRIBUTING.md)
- [ ] Layering is respected: `src/` projects add no upward or sideways dependencies, and no NuGet dependencies (BCL only)
- [ ] Wire parsers never throw on hostile input (truncation/malformation returns `false`/drops, never an exception)
- [ ] Protocol behavior is backed by a test that cites its RFC and section
- [ ] Security-sensitive changes (`Keryx.Dtls`, `Keryx.Srtp`) never weaken a verification step and cite the relevant RFC
- [ ] Public API changes are documented (README / XML docs)
- [ ] Commits are scoped, signed off (`git commit -s`, DCO), and messages explain the "why"

## Notes for reviewers

<!-- Anything non-obvious: tradeoffs, follow-ups, areas you'd like extra eyes on. -->
