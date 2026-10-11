#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Self-test for policy-diff-guard.

Three required test classes:
  A. Functional unit tests  (diff, risk tiers, verdicts, shadowing)
  B. Exception paths        (malformed perms, invalid policy shapes, bad files)
  C. Extreme edges          (empty policies, huge policies, colon-heavy scopes)

Pure standard library. Run: python self_test.py
"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from policy_diff import (expand, risk_of, newly_exposed, removed, shadowed,  # noqa: E402
                         report, blast_radius, generation_timeline,
                         rollback_suggestion)

results = []


def check(name, fn):
    try:
        fn()
        results.append((name, True, ""))
    except Exception as exc:  # noqa: BLE001
        results.append((name, False, "%s: %s" % (type(exc).__name__, exc)))


# ---------------------------------------------------------------- A. functional
def t_exactly_the_added_perms():
    old = {"allow": ["fs:/data/*:read", "tool:search:exec"]}
    new = {"allow": ["fs:/data/*:read", "tool:search:exec",
                     "fs:/etc/*:write", "net:api.internal:*"]}
    items = newly_exposed(old, new)
    assert {i["perm"] for i in items} == {"fs:/etc/*:write", "net:api.internal:*"}
    assert all(i["risk"] == "high" for i in items)


def t_risk_tiers():
    assert risk_of("fs", "write") == "high"
    assert risk_of("db", "exec") == "high"
    assert risk_of("net", "read") == "high"          # any network = high
    assert risk_of("fs", "read") == "medium"
    assert risk_of("tool", "search") == "low"


def t_no_change_is_auto_approvable():
    pol = {"allow": ["fs:/data/*:read", "net:api:x"]}
    txt, st = report(pol, pol)
    assert len(st["added"]) == 0 and "auto-approvable" in txt


def t_removed_reported():
    old = {"allow": ["fs:/data/*:read", "fs:/etc/*:write"]}
    new = {"allow": ["fs:/data/*:read"]}
    assert removed(old, new) == ["fs:/etc/*:write"]


def t_shadow_detection():
    old = {"allow": ["fs:/etc/hosts:read"]}
    new = {"allow": ["fs:/etc/hosts:read", "fs:/etc/*:write"]}
    sh = shadowed(old, new)
    assert len(sh) == 1 and sh[0]["new"] == "fs:/etc/*:write"
    txt, _ = report(old, new)
    assert "SHADOW" in txt and "REVIEW REQUIRED" in txt


def t_cover_semantics():
    assert expand("fs:/etc/*:write") == ("fs", "/etc/*", "write")
    # colon-heavy scope: Windows path survives as one scope
    assert expand("fs:C:/Users/x:*:read") == ("fs", "C:/Users/x:*", "read")
    assert expand("net:exec") == ("net", "*", "exec")
    assert expand("tool") == ("tool", "*", "*")


# ---------------------------------------------------------------- B. exceptions
def t_malformed_perm_does_not_crash():
    # 1-part perm expands to full wildcard; risk tier still assigned
    items = newly_exposed({"allow": []}, {"allow": ["weird-perm"]})
    assert items[0]["risk"] == "high" and items[0]["perm"] == "weird-perm"


def t_invalid_policy_shape():
    try:
        newly_exposed({"allow": "not-a-list"}, {"allow": []})
        assert False, "expected TypeError/AttributeError path"
    except TypeError:
        pass


def t_cli_loader_rejects_bad_file():
    from policy_diff import _load
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as fh:
        fh.write('{"allow": "oops"}')
    try:
        try:
            _load(path)
            assert False, "expected ValueError"
        except ValueError:
            pass
    finally:
        os.remove(path)


def t_missing_file_reported_via_cli(tmp=False):
    from policy_diff import _load
    try:
        _load(os.path.join("no", "such", "file.json"))
        assert False, "expected OSError"
    except OSError:
        pass


# ---------------------------------------------------------------- C. edges
def t_empty_policies():
    txt, st = report({"allow": []}, {"allow": []})
    assert st["added"] == [] and "auto-approvable" in txt
    assert newly_exposed({"allow": []}, {"allow": []}) == []


def t_huge_policy_diff():
    old = {"allow": ["tool:t%d:exec" % i for i in range(2000)]}
    new = {"allow": ["tool:t%d:exec" % i for i in range(2000)] +
                    ["net:host%d:*" % i for i in range(2000)]}
    items = newly_exposed(old, new)
    assert len(items) == 2000 and all(i["risk"] == "high" for i in items)


def t_scope_with_colons_and_globs():
    old = {"allow": []}
    new = {"allow": ["fs:C:/Program Files (x86)/app/*:read",
                     "api:v2:endpoints:read"]}
    items = newly_exposed(old, new)
    # read-only, non-net -> medium/low, never high
    assert all(i["risk"] in ("medium", "low") for i in items)


def t_unicode_scopes():
    old, new = {"allow": []}, {"allow": ["fs:/数据/目录/*:read"]}
    items = newly_exposed(old, new)
    assert items[0]["perm"] == "fs:/数据/目录/*:read"


def t_shadow_not_fired_for_same_perm():
    pol = {"allow": ["fs:/etc/*:write"]}
    assert shadowed(pol, pol) == []          # unchanged -> no warning
    old = {"allow": []}
    new = {"allow": ["fs:/etc/*:write"]}
    assert shadowed(old, new) == []          # nothing to shadow


# ------------------------------------------------ D. v0.1.2 differentiation
def t_blast_radius_zero_when_no_change():
    pol = {"allow": ["fs:/etc/*:write", "net:api:*"]}
    br = blast_radius(pol, pol)
    assert br["score"] == 0 and br["band"] == "none" and br["items"] == []


def t_blast_radius_weights_wildcard_and_sensitive():
    # high(5) x wildcard(2) x sensitive-prefix(3) = 30 -> severe
    br = blast_radius({"allow": []}, {"allow": ["fs:/etc/*:write"]})
    assert br["score"] == 30 and br["band"] == "severe"
    assert br["items"][0]["points"] == 30


def t_blast_radius_moderate_vs_severe():
    # medium(2) x wildcard(2) = 4; tool:search:exec parses act=exec -> high(5)
    # -> total 9, still "contained" (1-9)
    br = blast_radius({"allow": []},
                      {"allow": ["fs:/data/*:read", "tool:search:exec"]})
    assert br["score"] == 9 and br["band"] == "contained"
    worse = blast_radius({"allow": []},
                         {"allow": ["fs:/data/*:read", "fs:/etc/*:write"]})
    assert worse["score"] > br["score"] and worse["band"] == "severe"


def t_blast_radius_items_sorted_desc():
    br = blast_radius({"allow": []},
                      {"allow": ["tool:x:run", "net:db:*:read", "fs:/etc/hosts:write"]})
    pts = [i["points"] for i in br["items"]]
    assert pts == sorted(pts, reverse=True)


def t_timeline_counts_and_creep_flag():
    gens = [
        {"name": "v1", "policy": {"allow": ["fs:/data/*:read"]}},
        {"name": "v2", "policy": {"allow": ["fs:/data/*:read", "net:api:*:read"]}},
        {"name": "v3", "policy": {"allow": ["fs:/data/*:read", "net:api:*:read",
                                            "fs:/etc/*:write", "tool:x:exec"]}},
    ]
    tl = generation_timeline(gens)
    assert [g["name"] for g in tl["generations"]] == ["v1", "v2", "v3"]
    assert tl["generations"][1]["added"] == 1 and tl["generations"][1]["removed"] == 0
    assert tl["generations"][1]["high_added"] == 1   # net:api:*:read -> net = high
    assert tl["generations"][2]["high_added"] == 2   # /etc/*:write + exec
    assert tl["generations"][2]["cum_high"] == 3
    assert tl["creep"] is True and "grew" in tl["creep_note"]


def t_timeline_not_creep_when_removal_happens():
    gens = [
        {"name": "v1", "policy": {"allow": ["fs:/data/*:read"]}},
        {"name": "v2", "policy": {"allow": ["fs:/data/*:read", "net:api:*:read"]}},
        {"name": "v3", "policy": {"allow": ["fs:/data/*:read"]}},   # shrinks
    ]
    tl = generation_timeline(gens)
    assert tl["creep"] is False
    assert tl["generations"][2]["removed"] == 1


def t_timeline_single_generation():
    tl = generation_timeline([{"name": "only", "policy": {"allow": ["net:x:*"]}}])
    assert tl["creep"] is False and len(tl["generations"]) == 1
    assert tl["generations"][0]["added"] == 0


def t_timeline_empty_start_counts_first_gen_as_baseline():
    gens = [
        {"name": "empty", "policy": {"allow": []}},
        {"name": "v1", "policy": {"allow": ["tool:a:b"]}},
    ]
    tl = generation_timeline(gens)
    assert tl["generations"][0]["added"] == 0
    assert tl["generations"][1]["added"] == 1 and tl["creep"] is True


def t_rollback_removes_high_and_shadow_triggers():
    old = {"allow": ["fs:/etc/hosts:read"]}
    new = {"allow": ["fs:/etc/hosts:read", "fs:/etc/*:write", "net:api:*"]}
    rb = rollback_suggestion(old, new)
    assert set(rb["remove"]) == {"fs:/etc/*:write", "net:api:*"}
    assert rb["verified"] is True
    fixed = {"allow": [p for p in new["allow"] if p not in rb["remove"]]}
    txt, st = report(old, fixed)
    assert "auto-approvable" in txt
    assert not any(i["risk"] == "high" for i in st["added"])
    assert st["shadowed"] == []


def t_rollback_empty_when_clean_diff():
    old = {"allow": []}
    # act=find / act=read are non-high; no shadow -> nothing to remove
    new = {"allow": ["tool:search:find", "fs:/data/x:read"]}
    rb = rollback_suggestion(old, new)
    assert rb["remove"] == [] and rb["verified"] is True


def t_rollback_idempotent_on_no_change():
    pol = {"allow": ["net:api:*"]}
    rb = rollback_suggestion(pol, pol)
    assert rb["remove"] == [] and rb["verified"] is True


def t_cli_timeline_exit_codes():
    here = os.path.dirname(os.path.abspath(__file__))
    cli = os.path.join(here, "policy_diff.py")
    d = tempfile.mkdtemp()
    try:
        paths = []
        for i, perms in enumerate([["tool:a:b"],
                                   ["tool:a:b", "net:api:*:read"],
                                   ["tool:a:b", "net:api:*:read", "fs:/etc/*:write"]]):
            p = os.path.join(d, "v%d.json" % i)
            with open(p, "w", encoding="utf-8") as fh:
                json.dump({"allow": perms}, fh)
            paths.append(p)
        creep = subprocess.run([sys.executable, cli, "timeline"] + paths,
                               capture_output=True, text=True)
        assert creep.returncode == 1, creep.stdout + creep.stderr
        assert "CREEP" in creep.stdout
        flat = subprocess.run([sys.executable, cli, "timeline", paths[0], paths[0]],
                              capture_output=True, text=True)
        assert flat.returncode == 0, flat.stdout + flat.stderr
        cli_rb = subprocess.run([sys.executable, cli, "rollback", paths[0], paths[2]],
                                capture_output=True, text=True)
        assert cli_rb.returncode == 0, cli_rb.stdout + cli_rb.stderr
        assert "fs:/etc/*:write" in cli_rb.stdout
    finally:
        for p in paths:
            os.remove(p)
        os.rmdir(d)


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("t_"):
            check(name, fn)
    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, err in results:
        print("%-4s %s%s" % ("PASS" if ok else "FAIL", name,
                             ("  -> " + err) if err else ""))
    print("policy-diff-guard self-test: %d/%d PASS" % (passed, len(results)))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
