#!/usr/bin/env bash
#
# Live check for event time and UTC rendering on a throwaway Splunk container.
#
#   tests/live_event_time/rig.sh <data dir> <old macros.conf> [out dir] [splunk image]
#
# <data dir> holds base/otel-sample-200mb.log and compact/{encoded.log,templates.json}, as
# written by `./run.sh data encode` in log-10x/benchmarks splunk-license/. <old macros.conf>
# is the release to compare against, e.g. `git show v1.1.4:tenx-for-splunk/default/macros.conf`.
#
# Event time: the raw capture is indexed with Splunk's own timestamp extraction (the truth),
# and the compact events twice, once with the compact sourcetype as v1.1.4 set it and once
# with this checkout's. UTC rendering: fixture.py's events, expanded by the old and the new
# macro, by viewers in eight zones. Score with measure.py <out dir> <data dir>.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; APP="$(cd "$HERE/../.." && pwd)"
DATA="$1"; OLDMACROS="$2"; OUT="${3:-$HERE/out}"; IMAGE="${4:-splunk/splunk:10.4.3}"
C=tenx-event-time; PASS='Tim3Rig!2026'
mkdir -p "$OUT"
dx(){ timeout 900 docker exec "$@"; }
sp(){ dx -u splunk $C /opt/splunk/bin/splunk "$@"; }
q(){ sp search "$1" -app tenx-for-splunk -auth "admin:$PASS" -maxout 0 -preview false "${@:2}" 2>/dev/null; }
# tenx_dml by sourcetype: the app's scheduled Consume KV search writes its stash copies there too.
count(){ if [ "$1" = tenx_dml ]; then q "| tstats count where index=tenx_dml sourcetype=tenx_dml_raw_json" | tr -dc '0-9'; else q "| tstats count where index=$1" | tr -dc '0-9'; fi; }
say(){ printf '\n=== %s\n' "$*"; }
up(){ until dx -u splunk $C /opt/splunk/bin/splunk status 2>/dev/null | grep -q "splunkd is running"; do sleep 10; done; }

python3 "$HERE/fixture.py" "$OUT/dst"
docker rm -f -v $C >/dev/null 2>&1 || true
docker run -d --name $C -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_START_ARGS=--accept-license -e SPLUNK_PASSWORD="$PASS" -e TZ=UTC "$IMAGE" >/dev/null
say "waiting for splunkd"; up; sp version | head -1

say "indexes, sourcetypes, app, old macro"
: > "$OUT/indexes.conf"
for ix in truth tbefore tafter dst tenx_dml; do
  printf '[%s]\nhomePath = $SPLUNK_DB/%s/db\ncoldPath = $SPLUNK_DB/%s/colddb\nthawedPath = $SPLUNK_DB/%s/thaweddb\n' \
    "$ix" "$ix" "$ix" "$ix" >> "$OUT/indexes.conf"
done
cat > "$OUT/props.conf" <<'EOF'
# Truth: Splunk's own timestamp extraction on the raw lines, a zoneless timestamp read as UTC.
[tenx_raw_ts]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TRUNCATE = 0
TZ = UTC
CHARSET = UTF-8
KV_MODE = none
# Before: the compact sourcetype as v1.1.4 set it.
[tenx_enc_before]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TRUNCATE = 262144
DATETIME_CONFIG = CURRENT
EOF
docker cp "$OUT/indexes.conf" $C:/opt/splunk/etc/system/local/indexes.conf
docker cp "$OUT/props.conf" $C:/opt/splunk/etc/system/local/props.conf
rm -rf "$OUT/stage"; mkdir -p "$OUT/stage"; cp -R "$APP/tenx-for-splunk" "$OUT/stage/"
find "$OUT/stage" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
mkdir -p "$OUT/stage/tenx-for-splunk/local"
python3 - "$OLDMACROS" "$OUT/stage/tenx-for-splunk/local/macros.conf" <<'PY'
import sys
line = [l for l in open(sys.argv[1]).read().split("\n") if l.startswith("definition = ") and "| fields" in l][0]
open(sys.argv[2], "w").write("[tenx-inflate-old]\n" + line + "\n")
PY
docker cp "$OUT/stage/tenx-for-splunk" $C:/opt/splunk/etc/apps/tenx-for-splunk
dx -u root $C chown -R splunk:splunk /opt/splunk/etc/apps/tenx-for-splunk /opt/splunk/etc/system/local
sp restart >/dev/null; up

say "ingest"
dx -u root $C mkdir -p /data
docker cp "$DATA/base/otel-sample-200mb.log" $C:/data/raw.log
docker cp "$DATA/compact/encoded.log" $C:/data/enc.log
docker cp "$OUT/dst/events.log" $C:/data/dst.log
docker cp "$OUT/dst/templates.json" $C:/data/dst_tpl.json
dx -u root $C chown -R splunk:splunk /data
sp add oneshot /data/raw.log -index truth -sourcetype tenx_raw_ts -auth "admin:$PASS" >/dev/null 2>&1
sp add oneshot /data/enc.log -index tbefore -sourcetype tenx_enc_before -auth "admin:$PASS" >/dev/null 2>&1
sp add oneshot /data/enc.log -index tafter -sourcetype tenx_encoded -auth "admin:$PASS" >/dev/null 2>&1
sp add oneshot /data/dst_tpl.json -index tenx_dml -sourcetype tenx_dml_raw_json -auth "admin:$PASS" >/dev/null 2>&1
sp add oneshot /data/dst.log -index dst -sourcetype tenx_encoded -auth "admin:$PASS" >/dev/null 2>&1
for pair in "truth $(wc -l < "$DATA/base/otel-sample-200mb.log")" "tbefore $(wc -l < "$DATA/compact/encoded.log")" \
            "tafter $(wc -l < "$DATA/compact/encoded.log")" "dst $(wc -l < "$OUT/dst/events.log")" "tenx_dml 4"; do
  set -- $pair; t0=$SECONDS
  until [ "$(count $1)" = "$2" ]; do [ $((SECONDS-t0)) -lt 2400 ] || { echo "timeout on $1: $(count $1)/$2"; exit 1; }; sleep 15; done
  echo "$1: $2"
done
if dx -u splunk $C grep -q "Error compiling INGEST_EVAL" /opt/splunk/var/log/splunk/splunkd.log; then
  dx -u splunk $C grep "Error compiling INGEST_EVAL" /opt/splunk/var/log/splunk/splunkd.log; exit 1
fi

say "fixture templates into the KV store"
q 'index=tenx_dml sourcetype=tenx_dml_raw_json earliest=0 | sendalert tenx_dml_to_kv' >/dev/null; sleep 20

say "export: event time"
q 'index=truth earliest=0 latest=+10y | eval h=sha256(_raw), t=printf("%.6f",_time), ts=if(isnull(timestartpos),"",timestartpos) | table h t ts' -output csv > "$OUT/truth.csv"
for ix in tbefore tafter; do
  q "index=$ix earliest=0 latest=+10y | eval h=sha256(_raw), t=printf(\"%.6f\",_time), it=_indextime | table h t it" -output csv > "$OUT/$ix.csv"
done
q '| walklex index=tafter type=field | stats count by field' -output csv > "$OUT/tafter_indexed_fields.csv"

say "export: rendering"
for z in UTC America/New_York Europe/London Australia/Sydney Pacific/Chatham America/Adak Asia/Kolkata Etc/GMT-4; do
  sp _internal call /services/authentication/users/admin -post:tz "$z" -auth "admin:$PASS" >/dev/null 2>&1
  f=$(echo "$z" | tr '/' '_')
  for m in tenx-inflate-old tenx-inflate; do
    q "index=dst earliest=0 latest=+10y | eval c=_raw | \`$m\` | table c _raw" -output csv > "$OUT/dst_${f}_${m}.csv"
  done
  echo "$z"
done
sp _internal call /services/authentication/users/admin -post:tz UTC -auth "admin:$PASS" >/dev/null 2>&1
say "done; container $C left up (docker rm -f -v $C)"
