#!/usr/bin/env python3
"""Validate data/kb_data.json: identifiers, required fields, cross-references and counts.

Checks
  * every entity has a well-formed id, a non-empty name, and unique ids within its collection
  * every cross-reference (CAPEC<->CWE, CWE/CVE/CAPEC/killchain/PTES -> ATT&CK, D3FEND counters,
    detection profiles -> ATT&CK) resolves to an entity that exists in the dataset
  * meta.counts matches the real collection sizes
  * out-of-subset references must appear in build/known_external_refs.json (stale entries fail)
  * CAPEC<->CWE links are reciprocal (reported as warnings, since curation can be one-sided)

Exit 0 when valid, 1 on any error. Usage: python3 build/validate_data.py [path/to/kb_data.json]
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TECH_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
CAPEC_ID = re.compile(r"^CAPEC-\d+$")
CWE_ID = re.compile(r"^CWE-\d+$")
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
D3_ID = re.compile(r"^D3-[A-Z]{2,5}$")
TA_ID = re.compile(r"^TA\d{4}$")


def ids(items):
    return [i.get("id") for i in items if isinstance(i, dict)]


def main(path: Path) -> int:
    errors, warnings = [], []
    data = json.loads(path.read_text(encoding="utf-8"))
    allow_path = ROOT / "build" / "known_external_refs.json"
    allowed = {(a["from"], a["to"]) for a in json.loads(allow_path.read_text(encoding="utf-8"))["allow"]} \
        if allow_path.exists() else set()
    used = set()

    # ---- ATT&CK technique universe (enterprise + ICS + mobile, including sub-techniques)
    attack_techs = data["attack"]["techniques"]
    tech_ids = set()
    for coll in ("attack", "ics", "mobile"):
        for t in data[coll]["techniques"]:
            tech_ids.add(t["id"])
            for s in t.get("subs") or []:
                sid = s.get("id") if isinstance(s, dict) else s
                if sid:
                    tech_ids.add(sid)
    capec_ids = set(ids(data["capec"]))
    cwe_ids = set(ids(data["cwe"]))
    d3_ids = set(ids(data["d3fend"]["techniques"]))

    # ---- per-collection: id format, unique ids, required text
    def check_collection(name, items, id_re=None, text_fields=("name",)):
        seen = set()
        for it in items:
            iid = it.get("id")
            where = f"{name}:{iid}"
            if not iid:
                errors.append(f"{name}: entry without id")
                continue
            if id_re and not id_re.match(iid):
                errors.append(f"{where}: malformed id")
            if iid in seen:
                errors.append(f"{where}: duplicate id")
            seen.add(iid)
            for f in text_fields:
                if not str(it.get(f, "")).strip():
                    errors.append(f"{where}: empty '{f}'")

    check_collection("attack.techniques", attack_techs, TECH_ID)
    check_collection("ics.techniques", data["ics"]["techniques"], TECH_ID)
    check_collection("mobile.techniques", data["mobile"]["techniques"], TECH_ID)
    check_collection("capec", data["capec"], CAPEC_ID)
    check_collection("cwe", data["cwe"], CWE_ID)
    check_collection("cve", data["cve"], CVE_ID, text_fields=("desc",))
    check_collection("d3fend", data["d3fend"]["techniques"], D3_ID)
    for coll in ("killchain", "ptes", "wstg", "owasp_top10", "nist_csf", "nist_800115"):
        check_collection(coll, data[coll])
    check_collection("courses", data["courses"])

    # ---- cross-references
    def need(where, target_set, refs, label):
        for r in refs or []:
            if r not in target_set:
                if (where, r) in allowed:
                    used.add((where, r))
                else:
                    errors.append(f"{where}: {label} '{r}' does not exist")

    for t in attack_techs + data["ics"]["techniques"] + data["mobile"]["techniques"]:
        pass  # technique->capec/cwe refs live on enterprise techniques
    for t in attack_techs:
        need(f"attack:{t['id']}", capec_ids, t.get("capec"), "CAPEC")
        need(f"attack:{t['id']}", cwe_ids, t.get("cwe"), "CWE")
    for c in data["capec"]:
        need(f"capec:{c['id']}", cwe_ids, c.get("cwe"), "CWE")
        need(f"capec:{c['id']}", tech_ids, c.get("attack"), "ATT&CK technique")
    for w in data["cwe"]:
        need(f"cwe:{w['id']}", capec_ids, w.get("capec"), "CAPEC")
        need(f"cwe:{w['id']}", tech_ids, w.get("attack"), "ATT&CK technique")
    for v in data["cve"]:
        need(f"cve:{v['id']}", cwe_ids, v.get("cwe"), "CWE")
        need(f"cve:{v['id']}", tech_ids, v.get("attack"), "ATT&CK technique")
    for k in data["killchain"]:
        need(f"killchain:{k['id']}", tech_ids, k.get("attack"), "ATT&CK technique")
        need(f"killchain:{k['id']}", capec_ids, k.get("capec"), "CAPEC")
    for p in data["ptes"]:
        need(f"ptes:{p['id']}", tech_ids, p.get("attack"), "ATT&CK technique")
    for o in data["owasp_top10"]:
        need(f"owasp:{o['id']}", cwe_ids, o.get("cwe"), "CWE")
    for d in data["d3fend"]["techniques"]:
        need(f"d3fend:{d['id']}", tech_ids, d.get("counters"), "ATT&CK technique")
    for tid in data["detection"]["techniques"]:
        if tid not in tech_ids:
            errors.append(f"detection:{tid}: ATT&CK technique does not exist")

    for pair in sorted(allowed - used):
        errors.append(f"stale allowlist entry {pair[0]} -> {pair[1]}: target now resolves or no longer referenced; remove it")

    # ---- CAPEC <-> CWE reciprocity (warning only)
    capec_cwe = {c["id"]: set(c.get("cwe") or []) for c in data["capec"]}
    for w in data["cwe"]:
        for cap in w.get("capec") or []:
            if cap in capec_cwe and w["id"] not in capec_cwe[cap]:
                warnings.append(f"{cap} lists {w['id']} as a CWE child only one way")

    # ---- meta.counts must match the data
    counts = data["meta"].get("counts", {})
    actual = {
        "attack_tactics": len(data["attack"]["tactics"]),
        "attack_techniques": len(attack_techs),
        "ics_techniques": len(data["ics"]["techniques"]),
        "mobile_techniques": len(data["mobile"]["techniques"]),
        "d3fend": len(data["d3fend"]["techniques"]),
        "capec": len(data["capec"]),
        "cwe": len(data["cwe"]),
        "cve": len(data["cve"]),
        "detection_profiles": len(data["detection"]["techniques"]),
        "telemetry_sources": len(data["detection"]["telemetry"]),
        "courses": len(data["courses"]),
    }
    for k, v in actual.items():
        if k in counts and counts[k] != v:
            errors.append(f"meta.counts.{k} is {counts[k]} but the data contains {v}")

    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"error: {e}")
    if errors:
        print(f"FAIL: {len(errors)} error(s)")
        return 1
    print(f"OK: {len(tech_ids)} techniques, {len(capec_ids)} CAPEC, {len(cwe_ids)} CWE, {len(data['cve'])} CVE checked")
    return 0


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "kb_data.json"
    sys.exit(main(target))
