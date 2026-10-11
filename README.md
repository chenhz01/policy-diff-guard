# policy-diff-guard

**Agent permission policies creep: a 3-line diff can silently hand your agent write access to `/etc`. This tool statically annotates what a policy change NEWLY exposes — files, hosts, APIs — before you approve it.** You need it if agent permissions are reviewed by humans. Skip it if you need runtime enforcement (this reviews diffs; it does not guard execution). ~360 lines, pure Python stdlib.

---

## Problem

Runtime guardrails see violations only *during* execution — after the merge, after the deploy, sometimes after the damage. The interesting question for a reviewer is earlier and narrower: **"compared to the current policy, what can the agent reach that it could not reach before?"** Answering that by eyeballing a JSON diff fails for three reasons:

1. **Permission creep** — individually reasonable grants compound; nobody tracks cumulative reachability.
2. **Wildcard blindness** — `fs:/etc/*:write` looks like one harmless line next to ten read grants, but its scope covers all of them.
3. **Asymmetric visibility** — removed lines (risk-reducing) and added lines (risk-increasing) look identical in a plain diff.

This is the policy-change-review side of agent sandboxing (formalized in some hardened agent runtimes as "prove what this diff unlocks"), extracted as a standalone static tool you can bolt onto any PR workflow.

## How it works

```
 old_policy.json      new_policy.json
      │                     │
      ▼                     ▼
 ┌─────────────────────────────────────────────┐
 │ parse perms:  domain : scope : action       │
 │ (first token = domain, LAST = action,       │
 │  middle = scope, so colon-heavy scopes      │
 │  like 'C:/Users/x:*' survive)               │
 └───────────────┬─────────────────────────────┘
                 ▼
   set-diff on allow-lists
   ┌───────────┬─────────────┬─────────────────┐
   │  added    │  removed    │  shadowed       │
   │  (risk↑)  │  (risk↓)    │  new wildcard   │
   │           │             │  covers an old  │
   │           │             │  grant's scope  │
   └─────┬─────┴──────┬──────┴────────┬────────┘
         ▼            ▼               ▼
   risk tiers:  high = write/exec/net grants
                medium = read grants
                low  = everything else
         └────────────┴───────────────┘
                      ▼
   verdict: REVIEW REQUIRED if any high or shadow
            (CLI exits 1 so CI can gate on it)
```

On top of the diff, v0.1.2 adds three read-only lenses over the same set-diff core: `blast_radius` (weighted point score of the newly reachable surface), `generation_timeline` (N-version creep trend), and `rollback_suggestion` (minimal verified removal set). None of them change the verdict semantics above; blast radius is reported alongside the verdict, timeline and rollback are separate subcommands.

## Quickstart

```bash
# ~5 seconds: self-test (27 cases, pure stdlib)
python self_test.py

# ~1 min: annotate a real diff (exit code 1 = review required)
python policy_diff.py diff old_policy.json new_policy.json
python policy_diff.py diff old_policy.json new_policy.json --json   # machine-readable, includes blast_radius

# ~1 min: creep trend across N consecutive versions (exit 1 = monotonic growth)
python policy_diff.py timeline v1.json v2.json v3.json

# ~1 min: minimal removal set that restores auto-approvability
python policy_diff.py rollback old_policy.json new_policy.json

# ~5 min to integrate: add to CI as a merge gate
python policy_diff.py diff "$OLD" "$NEW" || echo "human review required"

# ~1 min: lint one policy file by risk tier
python policy_diff.py check current_policy.json
```

## How this differs from iam-diff-visualizer

The closest direct anchor is [AshwinNHacker/iam-diff-visualizer](https://github.com/AshwinNHacker/iam-diff-visualizer): it diffs two AWS IAM policies at the *effective-grant* level and annotates security impact. Per its README it already does: IAM document parsing (Statement/Action/Resource/Condition), wildcard expansion via a 6,671-action botocore-mined catalogue, Allow-vs-Deny effective-permission resolution, effective-set diffing with resource-scope-widening callouts, a risk ruleset covering high-risk actions and multi-action privilege-escalation combinations (introduced vs resolved), a self-contained HTML report plus JSON, a `--fail-on-risk` CI gate, single-policy `analyze`, and an optional Flask web UI. It is the stronger tool for AWS IAM review; credit where due.

What this repo adds that the anchor's README does not document (checked 2026-10-11):

1. **Quantified blast radius** — every newly added perm gets a deterministic point score (risk-tier weight × wildcard multiplier × sensitive-prefix multiplier), banded none/contained/elevated/severe, included in both text and `--json` output. The anchor reports counts and categorical findings; no weighted numeric scoring appears in its README.
2. **Generation timeline with creep detection** — `timeline v1.json v2.json v3.json` walks N consecutive policy versions, counts added/removed/high-added per generation, and flags monotonic allow-list growth (the signature of creep across diffs that each individually passed review). The anchor's README only shows pairwise `compare` and single-policy `analyze`; no multi-version trend.
3. **Generated rollback suggestion** — `rollback` emits the minimal removal set (all new high-risk perms + all shadow-triggering grants) and re-runs the diff to verify the result is auto-approvable. The anchor README ships a hand-written remediated example file; it does not document generating a remediation/removal set.

Honest asymmetry: the anchor has capabilities this tool deliberately lacks — concrete-action expansion (our perms stay symbolic), Deny handling (allow-lists only, documented), escalation-combination rules, and HTML reports. The scopes are also different inputs: AWS IAM documents vs generic agent `domain:scope:action` allow-lists.

## Comparison: why not X?

| Alternative | When does it catch the risk? | Understands wildcards/scope? | Adoption cost | Verdict |
|---|---|---|---|---|
| Runtime guardrails | During execution (post-merge) | Yes, per-call | Framework-specific | Necessary, but too late for review |
| Manual policy review | At review, if lucky | No — creep and wildcards defeat eyeballs | Zero | Scales badly; this tool augments it |
| Full policy engines (OPA-class) | Pre-deploy, but requires policy language migration | Yes | Rewrite policies in their DSL | Right for greenfield; overkill for "annotate my JSON diff" |
| Plain `git diff` on the JSON | Textual only | No | Zero | Shows changed lines, not new reachability |
| **policy-diff-guard** | **Pre-merge** | Yes (scope coverage + shadow detection) | ~0 (your existing JSON) | The missing review-layer piece |

## Minimal Fallback

No CI, no integration budget? Two degrade paths:

- **One-file lint**: `python policy_diff.py check policy.json` ranks every grant in your current policy by static risk — a 30-second audit with zero integration.
- **Copy the risk table**: the entire tiering logic is one function (`risk_of`) and one table; paste it into any review checklist or linter in any language.

## Design Trade-offs

Priority order when conflicts arise: **no false all-clears > coverage of risks > convenience**.

- **Allow-lists only.** Deny-lists invert the analysis (you must prove unreachability) and are out of scope at this size; the report is honest about that rather than pretending.
- **Static tiers, not contextual risk.** `net:*:read` is flagged high because network reachability is the common exfiltration path, even though some reads are benign. Expect false alarms in the high tier; that is the deliberate direction (a false all-clear is the unforgivable failure mode for a reviewer aid).
- **Shadow = scope coverage, action-agnostic.** A new `fs:/etc/*:write` warns against an existing `fs:/etc/hosts:read` even though "write ⊅ read" formally — the point is the scope just got broadly granted, which the line-count of the diff hides.
- **Exact set-diff, no semantic merging.** Two spellings of the same grant count as different perms. Simple and predictable beats clever normalization that could hide a real change.

## Limits & Second-order Effects

- **Review theater**: teams may rubber-stamp "REVIEW REQUIRED" diffs once the verdict becomes routine; the tool ranks risk but cannot rank *intent*.
- **Deny-list blind spot**: policies that combine allow and deny lists are analyzed on the allow side only; a loosened deny is invisible here (documented, not silently mishandled).
- **Gaming**: agents or developers can structure changes as many small auto-approvable diffs; cumulative drift returns. Mitigation: periodically run `check` on the full policy, not just diffs.
- **False confidence in scope strings**: if your scope globs are themselves buggy (e.g., `/etc/*` not matching `/etc/ssh/...` in your runtime's matcher), this tool faithfully reproduces your matcher's assumptions — not your runtime's actual behavior.

## FAQ

**Q: When should I NOT use this tool?**
When your policies are deny-list based, when grants carry conditions (time windows, per-request quotas) that change reachability without changing the allow-list, or when you already enforce formal pre-deploy verification — this tool would be a weaker duplicate. Also skip it as a *substitute* for runtime enforcement; it is a review aid, not a guard. (Confidence: High — structural.)

**Q: Why is every network grant "high"? A read-only API call is harmless.**
Exfiltration is a read. Treating network reads as low-risk is how "harmless" APIs become data-export channels. Downgrade consciously, in your fork, with a written reason. (Confidence: High for the default; Medium that your context matches it.)

**Q: Does it handle policy formats other than `{"allow": [...]}`?**
No — and that is the point of a ~360-line tool. Convert your format with a 5-line adapter; the diff/shadow/risk core is format-agnostic.

**Q: What is a "shadow warning" exactly?**
A newly added grant whose scope covers an existing grant's scope. The diff stays small but effective reachability jumps. Reviewers see `[SHADOW]` with both perms.

**Q: Why exit code 1 on high risk instead of a special code?**
So `|| echo "review required"` and CI gate syntax work with zero configuration. Standard Unix composability over expressive exit codes.

## [Core Assumptions]

1. Policies are allow-lists of string perms `domain:scope:action` with `*` wildcards; richer policy languages are out of scope.
2. Risk is a static property of (domain, action), not of context — the tool ranks exposure, never intent.
3. Reviewers act on the report; the tool does not and must not auto-apply or auto-revert anything.
4. Scope strings in your runtime match `fnmatch` glob semantics; if your runtime uses different matching, shadow detection's precision degrades accordingly.
5. Set-diff on exact perm strings is the correct change semantics (no normalization) — spelling changes should be reviewed, not hidden.

## Key conclusions (with confidence)

- Static pre-merge annotation catches the wildcard-blindness failure mode that manual diff review reliably misses — **High** (structural: reviewers read line counts, not scope coverage; shadow detection exists precisely for this).
- Default risk tiers (write/exec/net = high) will over-alert in read-heavy environments — **High** (by design; direction of error chosen to avoid false all-clears).
- The tool reduces permission-creep incidents in teams that adopt it as a CI gate — **Medium** [estimated]; no incident data ships with this repo, per the honesty rule. Measure your own before/after.

Data reflecting repo state and test counts: as of 2026-10-11.

## License

MIT — see [LICENSE](LICENSE). Contact: hcac4735@agent.qq.com
