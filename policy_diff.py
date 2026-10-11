#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
policy-diff-guard -- Static risk annotator for AI-agent permission changes.

Input: two policy JSON documents, each of the form
    {"allow": ["fs:/data/*:read", "tool:search:exec", ...]}
Output: a human-readable report of what the change NEWLY exposes
(files / hosts / APIs the agent could not reach before), risk-ranked,
plus removals (shrinking = risk-reducing, reported for completeness)
and wildcard-shadowing warnings (a new broad grant that silently covers
an existing narrow grant).

This is a PRE-merge review aid: it shows blast radius before approval.
It does not enforce anything at runtime. Pure stdlib. MIT.
"""
import argparse
import fnmatch
import json
import sys

RISK = {"*:write": "high", "*:exec": "high", "net:*": "high",
        "*:read": "medium", "fs:read": "medium"}
RANK = {"high": 0, "medium": 1, "low": 2}
HIGH_RISK_ACTIONS = {"write", "exec"}

# ---- v0.1.2: quantified blast radius ---------------------------------------
WEIGHT = {"high": 5, "medium": 2, "low": 1}
WILDCARD_MULT = 2       # a trailing/inner '*' in the scope multiplies reach
SENSITIVE_MULT = 3      # scope touching a sensitive prefix multiplies impact
SENSITIVE_PREFIXES = ("/etc", "/root", "/home", "/var/run", "/proc", "/sys",
                      ".ssh", ".aws", ".env", "c:/windows", "c:/program files")
BANDS = ((0, "none"), (9, "contained"), (29, "elevated"))  # else "severe"


def expand(perm):
    """'fs:/data/*:read' -> (domain, scope, action). Wildcards preserved.

    Rule: domain = first ':'-token, action = LAST ':'-token, scope =
    everything in between. This keeps colon-heavy scopes intact:
      'fs:C:/Users/x:*:read'     -> ('fs', 'C:/Users/x:*', 'read')
      'api:v2:endpoints:read'    -> ('api', 'v2:endpoints', 'read')
      'net:exec'                 -> ('net', '*', 'exec')
      'tool'                     -> ('tool', '*', '*')
    """
    if ":" not in perm:
        return (perm, "*", "*")
    dom, rest = perm.split(":", 1)
    if ":" not in rest:
        return (dom, "*", rest)
    scope, act = rest.rsplit(":", 1)
    return (dom, scope, act)


def _allow(policy):
    """API-boundary validation: 'allow' must be a list of strings."""
    allow = policy.get("allow", [])
    if not isinstance(allow, list) or not all(isinstance(p, str) for p in allow):
        raise TypeError('policy["allow"] must be a list of strings')
    return allow


def risk_of(dom, act):
    """Static risk tier for a (domain, action) grant."""
    if act in HIGH_RISK_ACTIONS or act == "*":
        return "high"
    if dom == "net":
        return "high"
    return RISK.get("%s:%s" % (dom, act), "low")


def _covers_scope(broad, narrow):
    """True if perm tuple `broad` grants access to every target `narrow`'s
    scope reaches (domain + scope only; action differences are irrelevant
    for shadowing, because the *scope* is what got bigger)."""
    bd, bs, _ = broad
    nd, ns, _ = narrow
    if bd != "*" and bd != nd and not fnmatch.fnmatch(nd, bd):
        return False
    if bs == "*":
        return True
    return fnmatch.fnmatch(ns, bs)


def newly_exposed(old_policy, new_policy):
    """Perms present in new_policy but not in old_policy, risk-annotated."""
    old = set(_allow(old_policy))
    added = [p for p in _allow(new_policy) if p not in old]
    out = []
    for perm in added:
        dom, scope, act = expand(perm)
        out.append({"perm": perm, "risk": risk_of(dom, act),
                    "exposes": "newly reachable: %s::%s [%s]" % (dom, scope, act)})
    return sorted(out, key=lambda x: RANK[x["risk"]])


def removed(old_policy, new_policy):
    """Perms the change takes away (risk-reducing; reported, not alarmed)."""
    new = set(_allow(new_policy))
    return sorted(p for p in _allow(old_policy) if p not in new)


def shadowed(old_policy, new_policy):
    """New grants whose scope subsumes an existing grant's scope.

    Example: adding 'fs:/etc/*:write' when 'fs:/etc/hosts:read' already
    exists means the diff *looks* small but the effective scope is large.
    """
    old_set = set(_allow(old_policy))
    new_set = set(_allow(new_policy))
    added = list(new_set - old_set)
    warnings = []
    for a in added:
        for o in old_set:
            if o != a and _covers_scope(expand(a), expand(o)) and o not in added:
                warnings.append({"new": a, "shadows": o})
                break
    return warnings


def report(old_policy, new_policy):
    items = newly_exposed(old_policy, new_policy)
    gone = removed(old_policy, new_policy)
    shadow = shadowed(old_policy, new_policy)
    blast = blast_radius(old_policy, new_policy)
    lines = ["POLICY DIFF REPORT",
             "newly added perms: %d | removed perms: %d | shadow warnings: %d"
             % (len(items), len(gone), len(shadow)),
             "blast radius: %d (%s)" % (blast["score"], blast["band"])]
    for it in items:
        lines.append("  [+%-5s] %s  ->  %s"
                     % (it["risk"].upper(), it["perm"], it["exposes"]))
    for p in gone:
        lines.append("  [-REDUC] %s  ->  no longer reachable" % p)
    for w in shadow:
        lines.append("  [SHADOW] %s subsumes existing %s (bigger than it looks)"
                     % (w["new"], w["shadows"]))
    high = any(i["risk"] == "high" for i in items)
    lines.append("verdict: %s" % ("REVIEW REQUIRED" if (high or shadow)
                                  else "auto-approvable"))
    return "\n".join(lines), {"added": items, "removed": gone,
                              "shadowed": shadow, "blast_radius": blast}


# ---- v0.1.2: quantified blast radius ---------------------------------------
def _points(perm):
    dom, scope, act = expand(perm)
    pts = WEIGHT[risk_of(dom, act)]
    if "*" in scope:
        pts *= WILDCARD_MULT
    low = scope.lower()
    if any(pfx in low for pfx in SENSITIVE_PREFIXES):
        pts *= SENSITIVE_MULT
    return pts


def blast_radius(old_policy, new_policy):
    """Quantified score of the newly reachable surface.

    points(perm) = WEIGHT[risk] x WILDCARD_MULT(if scope has '*')
                   x SENSITIVE_MULT(if scope touches a sensitive prefix).
    Bands: 0 none / 1-9 contained / 10-29 elevated / >=30 severe.
    Deterministic by construction; the interesting output is the delta of
    the *same* scoring function across candidate diffs, not the absolute
    number.
    """
    old = set(_allow(old_policy))
    items = []
    total = 0
    for perm in _allow(new_policy):
        if perm in old:
            continue
        pts = _points(perm)
        total += pts
        items.append({"perm": perm, "points": pts,
                      "risk": risk_of(*expand(perm)[::2])})
    items.sort(key=lambda x: (-x["points"], x["perm"]))
    band = "severe"
    for threshold, name in BANDS:
        if total <= threshold:
            band = name
            break
    return {"score": total, "band": band, "items": items}


# ---- v0.1.2: policy generation timeline ------------------------------------
def generation_timeline(gens):
    """Trend across N consecutive policy generations.

    gens: list of {"name": str, "policy": {...}} oldest-first. For each
    generation after the first: added/removed counts, high-risk added count,
    net allow-list size, and cumulative high-risk count. creep=True when the
    allow-list size strictly grew at EVERY step -- the signature of
    permission creep that individually-auto-approvable diffs produce.
    """
    rows = []
    prev = None
    cum_high = 0
    grew_every_step = True
    for i, g in enumerate(gens):
        pol = g["policy"]
        size = len(set(_allow(pol)))
        if i == 0:
            rows.append({"name": g["name"], "size": size, "added": 0,
                         "removed": 0, "high_added": 0, "cum_high": 0})
        else:
            items = newly_exposed(prev, pol)
            high_added = sum(1 for it in items if it["risk"] == "high")
            cum_high += high_added
            gone = removed(prev, pol)
            rows.append({"name": g["name"], "size": size,
                         "added": len(items), "removed": len(gone),
                         "high_added": high_added, "cum_high": cum_high})
            if size <= rows[i - 1]["size"]:
                grew_every_step = False
        prev = pol
    creep = grew_every_step and len(rows) > 1 and rows[-1]["size"] > rows[0]["size"]
    note = ("allow-list size grew at every generation: cumulative permission "
            "creep across diffs that may each have been auto-approvable"
            if creep else "no monotonic growth across generations")
    return {"generations": rows, "creep": creep, "creep_note": note}


# ---- v0.1.2: rollback suggestion -------------------------------------------
def rollback_suggestion(old_policy, new_policy):
    """Minimal removal set that makes the change auto-approvable w.r.t. old.

    Removes every newly-added high-risk perm plus every shadow-triggering
    new grant, then re-runs the diff to verify nothing risky remains.
    Removals can only shrink the added set, so one pass is provably enough.
    """
    old = set(_allow(old_policy))
    new_list = _allow(new_policy)
    doomed = set()
    for it in newly_exposed(old_policy, new_policy):
        if it["risk"] == "high":
            doomed.add(it["perm"])
    for w in shadowed(old_policy, new_policy):
        doomed.add(w["new"])
    if not doomed:
        return {"remove": [], "verified": True}
    fixed = {"allow": [p for p in new_list if p not in doomed]}
    _, st = report(old_policy, fixed)
    verified = (not any(i["risk"] == "high" for i in st["added"])
                and not st["shadowed"])
    return {"remove": sorted(doomed), "verified": verified}


def _load(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or not isinstance(data.get("allow", []), list):
        raise ValueError("%s: expected {\"allow\": [perm, ...]}" % path)
    return data


# ---- CLI -------------------------------------------------------------------
def _cmd_diff(args):
    try:
        old, new = _load(args.old), _load(args.new)
    except (OSError, ValueError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    text, structured = report(old, new)
    if args.json:
        print(json.dumps(structured, indent=2, ensure_ascii=False))
    else:
        print(text)
    return 1 if (structured["added"] and
                 any(i["risk"] == "high" for i in structured["added"])) else 0


def _cmd_check(args):
    """Lint a single policy file: report high-risk and wildcard grants."""
    try:
        pol = _load(args.policy)
    except (OSError, ValueError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    for perm in _allow(pol):
        dom, scope, act = expand(perm)
        print("[%-6s] %s" % (risk_of(dom, act).upper(), perm))
    return 0


def _cmd_timeline(args):
    """N-generation creep trend; exit 1 when the allow-list monotonically grew."""
    try:
        gens = [{"name": p, "policy": _load(p)} for p in args.policies]
    except (OSError, ValueError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    if len(gens) < 2:
        sys.stderr.write("error: timeline needs at least 2 policy files\n")
        return 2
    tl = generation_timeline(gens)
    if args.json:
        print(json.dumps(tl, indent=2, ensure_ascii=False))
        return 1 if tl["creep"] else 0
    print("POLICY TIMELINE (%d generations, oldest first)" % len(gens))
    for r in tl["generations"]:
        print("  %-40s size=%-5d +%-3d -%-3d high+=%-2d cum_high=%d"
              % (r["name"], r["size"], r["added"], r["removed"],
                 r["high_added"], r["cum_high"]))
    print("verdict: %s (%s)" % ("CREEP" if tl["creep"] else "no monotonic creep",
                                tl["creep_note"]))
    return 1 if tl["creep"] else 0


def _cmd_rollback(args):
    """Suggest the minimal removal set that restores auto-approvability."""
    try:
        old, new = _load(args.old), _load(args.new)
    except (OSError, ValueError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    rb = rollback_suggestion(old, new)
    print(json.dumps(rb, indent=2, ensure_ascii=False))
    return 0 if rb["verified"] else 1


def build_parser():
    p = argparse.ArgumentParser(
        prog="policy_diff",
        description="Static risk annotation for AI-agent permission policy "
                    "changes: shows what a diff newly exposes, before merge.")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("diff", help="diff old policy vs new policy")
    d.add_argument("old", help="path to old policy JSON")
    d.add_argument("new", help="path to new policy JSON")
    d.add_argument("--json", action="store_true", help="emit structured JSON")
    d.set_defaults(func=_cmd_diff)

    c = sub.add_parser("check", help="lint one policy file by risk tier")
    c.add_argument("policy", help="path to policy JSON")
    c.set_defaults(func=_cmd_check)

    t = sub.add_parser("timeline", help="creep trend across >=2 policy "
                                        "generations (exit 1 on creep)")
    t.add_argument("policies", nargs="+",
                   help="policy JSON paths, oldest first")
    t.add_argument("--json", action="store_true", help="emit structured JSON")
    t.set_defaults(func=_cmd_timeline)

    r = sub.add_parser("rollback", help="minimal removal set that restores "
                                        "auto-approvability")
    r.add_argument("old", help="path to old policy JSON")
    r.add_argument("new", help="path to new policy JSON")
    r.set_defaults(func=_cmd_rollback)
    return p


if __name__ == "__main__":
    ns = build_parser().parse_args()
    sys.exit(ns.func(ns))
