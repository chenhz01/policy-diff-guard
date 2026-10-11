# Changelog

All notable changes to this project are documented here.
Format based on Keep a Changelog; versions are pre-1.0 reference releases.

## v0.1.2 - 2026-10-11 (round 3: differentiation vs iam-diff-visualizer)

Deep-read of the direct anchor (AshwinNHacker/iam-diff-visualizer) showed its README documents pairwise effective-set diffing with categorical risk findings — but no weighted numeric scoring, no multi-version trend, and no generated remediation. Three capabilities added on the existing set-diff core; none of the three appears in the anchor's README (checked 2026-10-11). Tests 15 -> 27 (+80%).

### Added
- **`blast_radius(old, new)`** — quantified score of the newly reachable surface: `points(perm) = WEIGHT[risk] × 2 (scope has '*') × 3 (scope touches a sensitive prefix)`, banded none/contained/elevated/severe; included in `diff` text and `--json` output.
- **`generation_timeline([{"name","policy"}, ...])`** — N-version trend: per-generation added/removed/high-added counts, cumulative high-risk count, and a `creep` flag when the allow-list size grew at every generation (monotonic growth across individually-passing diffs). New `timeline` CLI subcommand, exit 1 on creep, `--json` supported.
- **`rollback_suggestion(old, new)`** — minimal removal set (all new high-risk perms + all shadow-triggering grants), re-verified by re-running the diff so the result is provably auto-approvable. New `rollback` CLI subcommand.
- 12 new self_test cases covering blast-radius weighting/banding/sorting, timeline creep/no-creep/single-generation/empty-baseline semantics, rollback verification (including idempotent no-change), and CLI exit codes for `timeline`/`rollback`.

### Docs
- README: new "How this differs from iam-diff-visualizer" section (factual comparison, both directions — the anchor's stronger AWS-specific capabilities are credited, not minimized).

## v0.1.1 - 2026-10-11 (round 2: self-audit revision)

Second pass against the internal 16-item alignment checklist. Changes, each traceable to a checklist item:

### Fixed (correctness; test coverage 4 -> 15 cases, >20% improvement)
- **Colon-heavy scopes truncated**: `expand()` split on every `:`, so scopes like Windows paths (`fs:C:/Users/x:*:read`) or `api:v2:endpoints:read` were parsed into wrong domains. New rule: first token = domain, LAST token = action, middle = scope.
- **Invalid policy shapes silently accepted**: `{"allow": "not-a-list"}` iterated as characters instead of failing. All public functions now validate at the API boundary and raise `TypeError` with a precise message.
- **Shadow semantics corrected**: subsumption previously compared actions too, missing the most common trap (a new broad write grant covering an existing narrow read grant's scope). Shadowing is now scope-coverage-based, which is what "bigger than it looks" means for a reviewer.

### Added
- **Removals reporting**: risk-reducing lines now appear as `[-REDUC]` so a shrinking policy is visibly a shrinking policy (reviewers previously could not distinguish removals from additions in the output).
- **Shadow warnings** (`[SHADOW]`) folded into the verdict: any shadow forces `REVIEW REQUIRED`.
- argparse CLI: `diff` (exit 1 on high-risk added perms, CI-gate ready) and `check` (single-file risk lint); `--json` machine-readable output.
- `self_test.py`: 15 cases across functional units, exception paths, and extreme edges (empty policy, 4000-perm diff, unicode scopes, colon-heavy scopes).

### Docs
- Rewrote README to article depth: architecture diagram, 5-alternative comparison table, Minimal Fallback, Design Trade-offs with explicit priority order (no false all-clears first), Limits & Second-order Effects (review theater, deny-list blind spot), When-NOT-to-use FAQ, Core Assumptions, confidence-graded conclusions.

## v0.1.0 - 2026-10-11 (initial draft)

- Core diff: set-difference on allow-lists, static risk tiers (write/exec/net = high, read = medium, else low), plain-text report with `REVIEW REQUIRED` / `auto-approvable` verdict.
- Minimal README and 4-case inline self-test.
