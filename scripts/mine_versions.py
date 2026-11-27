"""Enrich src/data/vault-errors.json with per-entry Vault version ranges.

For each entry whose source file lives in hashicorp/vault, the entry's probe
literal is checked against that file at the latest patch release of every
minor version from 1.15 to the most recent (via releases.hashicorp.com).
Entries get `versions: {"since": ..., "until": ...}` when the probe is absent
at the floor or ceiling; most errors are stable and get no restriction.
"""
import json, re, os, sys, urllib.request, concurrent.futures

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
OUT = os.path.join(ROOT, "src", "data", "vault-errors.json")
SEED = os.path.join(ROOT, "scripts", "seed_catalog.py")
CACHE = os.path.expanduser("~/.cache/vault-version-probes")

def fetch(url, cachekey):
    os.makedirs(CACHE, exist_ok=True)
    p = os.path.join(CACHE, cachekey.replace("/", "_"))
    if os.path.exists(p):
        return open(p, encoding="utf-8", errors="replace").read()
    try:
        data = urllib.request.urlopen(url, timeout=20).read().decode("utf-8", "replace")
    except Exception:
        data = ""
    open(p, "w", encoding="utf-8").write(data)
    return data

def minor_key(m):
    return [int(x) for x in m.split(".")]

def main():
    idx = json.load(urllib.request.urlopen("https://releases.hashicorp.com/vault/index.json", timeout=20))
    latest = {}
    for v in idx["versions"]:
        if any(x in v for x in ("+", "-")):
            continue
        minor = ".".join(v.split(".")[:2])
        if minor_key(minor) < [1, 15]:
            continue
        if minor not in latest or [int(x) for x in v.split(".")] > [int(x) for x in latest[minor].split(".")]:
            latest[minor] = v
    minors = sorted(latest, key=minor_key)
    print("minors:", " ".join(minors))

    seed = open(SEED, encoding="utf-8").read()
    probes = {}
    for m in re.finditer(r'add\("([^"]+)"(.*?)(?=\nadd\(|\Z)', seed, re.S):
        pm = re.search(r'probe="((?:[^"\\]|\\.)*)"', m.group(2))
        if pm:
            probes[m.group(1)] = pm.group(1).encode().decode("unicode_escape")

    cat = json.load(open(OUT))
    files = set()
    targets = {}
    for e in cat["entries"]:
        src = e.get("source") or {}
        probe = probes.get(e["id"])
        if probe and src.get("repo") == "hashicorp/vault" and src.get("path"):
            targets[e["id"]] = (src["path"], probe)
            files.add(src["path"])
    print(f"probing {len(targets)} entries across {len(files)} files x {len(minors)} versions")

    jobs = [(minor, path) for minor in minors for path in files]
    content = {}
    def work(job):
        minor, path = job
        url = f"https://raw.githubusercontent.com/hashicorp/vault/v{latest[minor]}/{path}"
        return job, fetch(url, f"{minor}--{path}")
    with concurrent.futures.ThreadPoolExecutor(16) as ex:
        for job, text in ex.map(work, jobs):
            content[job] = text

    tagged = 0
    for eid, (path, probe) in targets.items():
        present = [minor for minor in minors if probe in content[(minor, path)]]
        e = next(x for x in cat["entries"] if x["id"] == eid)
        vers = {}
        if not present:
            print(f"  {eid}: probe not found in ANY version?! skipping")
            continue
        if minors[0] not in present:
            # A missing probe can mean the string moved files in a refactor, not
            # that the error is new: confirm it is absent anywhere in the 1.15 tree.
            import subprocess as sp
            r = sp.run(["grep", "-rl", "--include=*.go", "-F", probe, os.path.expanduser("/tmp/vault-115")], capture_output=True)
            hits = [l for l in r.stdout.decode().splitlines() if "_test" not in l]
            if hits:
                present.insert(0, minors[0])  # existed in 1.15 in another file
            else:
                vers["since"] = present[0]
        if minors[-1] not in present:
            vers["until"] = present[-1]
        if vers:
            e["versions"] = vers
            tagged += 1
            print(f"  {eid}: {vers}")
        else:
            e.pop("versions", None)
    cat["vault_versions"] = minors
    json.dump(cat, open(OUT, "w"), indent=2)
    open(OUT, "a").write("\n")
    print(f"done: {tagged} entries version-tagged")

if __name__ == "__main__":
    main()
