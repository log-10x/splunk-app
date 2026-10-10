"""Score the live rig. B6: each compact event's _time against the timestamp Splunk itself
extracts from the first line of that event's original text. B7: every fixture event's
expanded text against its expected UTC rendering, per viewer zone and macro."""
import csv, hashlib, json, sys, collections, pathlib, glob, os
csv.field_size_limit(10**9)
R = pathlib.Path(sys.argv[1]); DATA = pathlib.Path(sys.argv[2])  # rig output dir, benchmark data dir
sha = lambda s: hashlib.sha256(s.encode("utf-8", "surrogateescape")).hexdigest()

def rows(p):
    with open(p, newline="", encoding="utf-8", errors="surrogateescape") as f:
        return list(csv.DictReader(f))

out = {}
# ---- B6
truth = collections.defaultdict(set)
truth_has = {}
for r in rows(R/"truth.csv"):
    truth[r["h"]].add(round(float(r["t"]), 3))
    truth_has[r["h"]] = truth_has.get(r["h"], False) or (r["ts"] != "")
tpl_lines = {}
for line in open(DATA/"compact/templates.json", encoding="utf-8"):
    d = json.loads(line); tpl_lines[d["templateHash"]] = d["template"].count("\n") + 1
raw = open(DATA/"base/otel-sample-200mb.log", encoding="utf-8", errors="surrogateescape")
first_line_of = []   # per compact record: (compact sha, first original line sha)
for rec in open(DATA/"compact/encoded.log", encoding="utf-8", errors="surrogateescape"):
    rec = rec.rstrip("\n")
    h = rec[1:].split(",", 1)[0]
    k = tpl_lines[h]
    lines = [raw.readline().rstrip("\n") for _ in range(k)]
    first_line_of.append((sha(rec), sha(lines[0])))
assert raw.readline() == "", "walk did not consume the capture"
arms = {}
for arm in ("tbefore", "tafter"):
    m = collections.defaultdict(list)
    for r in rows(R/f"{arm}.csv"):
        m[r["h"]].append((float(r["t"]), float(r["it"])))
    arms[arm] = m
res = {}
for arm, m in arms.items():
    c = collections.Counter()
    for csha, lsha in first_line_of:
        got = m.get(csha)
        if not got: c["compact event not found"] += 1; continue
        if lsha not in truth: c["original line not found"] += 1; continue
        t_c, it = got[0]
        if truth_has[lsha]:
            c["line has a timestamp"] += 1
            tt = min(truth[lsha], key=lambda x: abs(x - t_c))
            if abs(tt - t_c) < 0.0005: c["matches to the millisecond"] += 1
            if int(tt) == int(t_c): c["matches to the second"] += 1
        else:
            c["line has no timestamp"] += 1
            if abs(t_c - it) < 1: c["no timestamp: _time is index time"] += 1
    res[arm] = dict(c)
out["B6"] = res
# ---- B7
exp = {}
for line in open(R/"dst/expected.tsv", encoding="utf-8"):
    n, text = line.rstrip("\n").split("\t", 1); exp[n] = text
b7 = {}
for f in sorted(glob.glob(str(R/"dst_*_tenx-inflate*.csv"))):
    name = os.path.basename(f)[4:-4]
    zone, macro = name.rsplit("_tenx-", 1)
    bad = []; total = 0
    for r in rows(f):
        n = r["c"].rsplit(",", 1)[1]; total += 1
        if r["_raw"] != exp[n]: bad.append((r["c"], r["_raw"], exp[n]))
    b7.setdefault(zone, {})["tenx-" + macro] = {"events": total, "wrong": len(bad), "examples": bad[:3]}
out["B7"] = b7
print(json.dumps(out, indent=1))
