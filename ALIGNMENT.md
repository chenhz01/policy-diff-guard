# Alignment Audit (Rules 85-100 / 16 items) — policy-diff-guard

Audit date: 2026-10-11 · Round-2 auditor: W1 · Round-3 re-audit (differentiation vs anchor): D2 · Version audited: v0.1.2

| # | Check | Status | Evidence |
|---|-------|--------|----------|
| 1 | Safety/Ethics section (safety-domain repos) | N/A | Static analyzer for permission-diff review; no exploit/OSINT/RE content. Defensive-security posture stated in README intro ("review aid, not a guard"). |
| 2 | Privacy: zero keys/tokens/real names; placeholders only | PASS | `grep -rEn "(sk-\|ghp_\|api[_-]?key\s*=\s*['\"][A-Za-z0-9])" .` → 0 hits; contact only `hcac4735@agent.qq.com`; no real names in any file. |
| 3 | Copyright: no >50-word copied text; LICENSE present | PASS | LICENSE (MIT, "zhengming contributors") exists; independent stdlib implementation. v0.1.2 "differs" section restates the anchor's features in original wording (no >50-word copied text; anchor README re-checked). |
| 4 | Fact-check labels on all numbers | PASS | Executable claims reproduce via `python self_test.py` (27/27 PASS); anchor capability list cross-checked against its README on 2026-10-11 and dated in the "differs" section; adoption-benefit claim remains [estimated]. |
| 5 | Confidence grading (≥2 labeled conclusions) | PASS | Key conclusions: High ×2, Medium [estimated] ×1, plus FAQ answer with High/Medium split — each with one-line rationale. |
| 6 | PLAN B / Minimal Fallback | PASS | README "Minimal Fallback": single-file `check` lint + copy-paste `risk_of` risk table. |
| 7 | Quickstart time budget | PASS | "~5 seconds" self-test, "~1 min" real diff / timeline / rollback, "~5 min" CI integration; staged path minimal → full. |
| 8 | Rule-conflict arbitration / priorities | PASS | Design Trade-offs opens with: no false all-clears > coverage of risks > convenience. |
| 9 | CHANGELOG ≥2 iterations with improvements listed | PASS | CHANGELOG.md v0.1.0 → v0.1.1 → v0.1.2; round-3 items enumerated per capability (blast radius, timeline, rollback) with test delta 15→27 traceable. |
| 10 | Exemption instructions (session-governance rule) | N/A | Session-level rule; not applicable to static repo content. |
| 11 | Time-sensitive data dated | PASS | README bottom: "as of 2026-10-11"; anchor-feature checks in the "differs" section dated 2026-10-11. |
| 12 | Explicit assumptions (≥3) | PASS | "[Core Assumptions]": 5 items (allow-list only, static risk, reviewer-in-loop, fnmatch semantics, no normalization). |
| 13 | Test triad: unit + exception + extreme edge, all PASS | PASS | `python self_test.py` → 27/27 PASS: functional + exception paths + extreme edges + v0.1.2 differentiation suite (blast radius, timeline, rollback, CLI exit codes). |
| 14 | Socratic FAQ incl. When NOT to use | PASS | FAQ Q1: "When should I NOT use this tool?" (deny-lists, conditional grants, runtime-enforcement substitution). |
| 15 | Pareto iteration round 3 with ≥20% improvement, traceable | PASS | Round 3 (differentiation): 3 new capabilities absent from the anchor README, each with stated factual basis; tests 15→27 (+80%); CHANGELOG v0.1.2 traceable per item. |
| 16 | ≤60-word first screen with need-to-use verdict | PASS | README first paragraph: 56 words, explicit "You need it if… / Skip it if…" judgment. |

**Summary: 13 PASS / 0 FAIL / 3 N-A (items 1, 10)** — re-audited at v0.1.2 after anchor differentiation round; no regressions vs the round-2 audit.

Anchor-differentiation note (D2): the direct anchor (AshwinNHacker/iam-diff-visualizer) was deep-read via its README on 2026-10-11. Its documented capability list and the three gaps this repo now fills are recorded in README "How this differs from iam-diff-visualizer". Honest asymmetry (capabilities the anchor has and we lack) is stated there too — the differentiation claim is two-directional, not one-sided.
