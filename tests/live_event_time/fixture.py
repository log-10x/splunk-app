"""DST fixture: templates with a timestamp slot, compact events at epochs around 2026 DST
transitions in several zones plus every 6 hours through 2026, and the expected UTC text."""
import json, sys, datetime as dt, pathlib
out = pathlib.Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
T = {
 "dstA": ("$(yyyy-MM-dd'T'HH:mm:ss.SSS'Z') INFO dst probe A $", lambda d,ms: f"{d:%Y-%m-%dT%H:%M:%S}.{ms:03d}Z INFO dst probe A"),
 "dstB": ("$(yyyy-MM-dd HH:mm:ss,SSS) WARN dst probe B $",       lambda d,ms: f"{d:%Y-%m-%d %H:%M:%S},{ms:03d} WARN dst probe B"),
 "dstC": ("$(MMM dd, yyyy hh:mm:ss a) dst probe C $",            lambda d,ms: f"{d:%b %d, %Y %I:%M:%S %p} dst probe C"),
 "dstD": ("$(yyyy-MM-dd HH:mm:ss Z) dst probe D $",              lambda d,ms: f"{d:%Y-%m-%d %H:%M:%S} +0000 dst probe D"),
}
U = dt.timezone.utc
transitions = ["2026-03-08T07:00","2026-11-01T06:00","2026-03-29T01:00","2026-10-25T01:00",
               "2026-04-04T16:00","2026-10-03T16:00","2026-04-04T14:00","2026-09-26T14:00",
               "2026-03-08T12:00","2026-11-01T11:00"]
epochs = set()
for t in transitions:
    c = dt.datetime.fromisoformat(t).replace(tzinfo=U)
    for k in range(-14*6, 14*6+1):
        epochs.add(int((c + dt.timedelta(minutes=10*k)).timestamp()))
start = dt.datetime(2026,1,1,tzinfo=U)
for k in range(0, 365*4): epochs.add(int((start + dt.timedelta(hours=6*k)).timestamp()))
epochs = sorted(epochs)
with open(out/"templates.json","w") as f:
    for h,(tpl,_) in T.items(): f.write(json.dumps({"templateHash":h,"template":tpl})+"\n")
n=0
with open(out/"events.log","w") as ev, open(out/"expected.tsv","w") as ex:
    for e in epochs:
        ms = (e*7) % 1000
        d = dt.datetime.fromtimestamp(e, U)
        for h,(_,fmt) in T.items():
            n += 1
            ev.write(f"~{h},{e*1000+ms},{n}\n")
            ex.write(f"{n}\t{fmt(d,ms)} {n}\n")
print(len(epochs), "epochs,", n, "events")
