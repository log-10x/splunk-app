#!/usr/bin/env bash
#
# Live gate: a heavy forwarder reads the compact events back from files and sends them with its own tcpout.
#
#   tests/live_hf_monitor/rig.sh <phase> [...]
#
#   phases, in order: build, config, pass t, clean, maps, pass m, drill, clean, report; down removes everything
#
# Environment:
#   W        work folder on the Docker host (required): secret/, data/, opt/tenx/, apps/, res/
#   PKG      the app package (.tar.gz) to test (required for config)
#   SAMPLES  folder holding win662.log, win4663.log (rendered Windows XML events), fgt100k.log and fgt239.log
#            (FortiGate key=value lines); hard-linked, never changed
#   ADDONS   folder holding Splunk_TA_windows, Splunk_TA_fortinet_fortigate, Splunk_SA_CIM (unpacked)
#   P        container prefix (default tenx-hfm), SUB the /24 of its Docker network (default 172.87.0)
#   RX       Receiver image (default log10x/edge-10x:1.1.181), FB fluent/fluent-bit:5.1.5,
#            SPLUNK splunk/splunk:10.4.3, UFIMG splunk/universalforwarder:10.4.3
#
# Four Splunk boxes: a Universal Forwarder sends the samples to a heavy forwarder, which parses them, writes
# the routed indexes to its ingest actions file destination and sends everything else to the indexer. Fluent
# Bit (two processes) and the Receivers run beside the heavy forwarder and write the compact events to
# /opt/tenx/compact/events/<pass>-<source>/, one JSON object per line, and the template records to
# /opt/tenx/compact/templates/. The heavy forwarder monitors those folders; the package's tenx-record-unwrap
# runs on them. A separate search head searches the indexer. No HTTP Event Collector anywhere.
#
# Each sample is read twice by the Universal Forwarder, with the same host and source: into hfm_<p>r_<s> (raw,
# never routed) and hfm_<p>_<s> (routed to the file, so it holds only the compact events). Checks print one
# line each, prefixed PASS or FAIL; res/summary.txt collects them.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${W:?set W}"; P=${P:-tenx-hfm}; SUB=${SUB:-172.87.0}
RX=${RX:-log10x/edge-10x:1.1.181}; FB=${FB:-fluent/fluent-bit:5.1.5}
SPLUNK=${SPLUNK:-splunk/splunk:10.4.3}; UFIMG=${UFIMG:-splunk/universalforwarder:10.4.3}
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null; unset AWS_PROFILE
NET=$P-net; IDX=$SUB.10; HF=$SUB.20; SH=$SUB.21; UF=$SUB.30; FBIP=$SUB.41
mkdir -p "$W/res"; SUM=$W/res/summary.txt
pw()  { cat "$W/secret/admin.pw"; }
log() { echo "$(date -u +%T) $*"; }
ok()  { local r=$1; shift; echo "$r $*" | tee -a "$SUM"; }
home(){ case "$1" in $P-uf) echo /opt/splunkforwarder;; *) echo /opt/splunk;; esac; }
ip()  { case "$1" in $P-idx) echo $IDX;; $P-hf) echo $HF;; $P-sh) echo $SH;; $P-uf) echo $UF;; esac; }
sp()  { local c=$1; shift; docker exec -u splunk "$c" "$(home "$c")/bin/splunk" "$@" 2>&1 | grep -v '^WARNING'; }
rest(){ local c=$1 m=$2 p=$3; shift 3; curl -sk -K <(printf 'user = "admin:%s"\n' "$(pw)") -X "$m" "https://$(ip "$c"):8089$p" "$@"; }
up200(){ [ "$(rest "$1" GET /services/server/info -o /dev/null -w '%{http_code}' 2>/dev/null)" = 200 ]; }
restart(){ sp "$1" restart >/dev/null 2>&1 || true; until up200 "$1"; do sleep 5; done; log "$1 restarted"; }
cp_app(){ local c=$1 src=$2 name=$3 h; h=$(home "$c"); docker exec -u root "$c" rm -rf "$h/etc/apps/$name"
  docker cp "$src" "$c:$h/etc/apps/$name" >/dev/null; docker exec -u root "$c" chown -R splunk:splunk "$h/etc/apps/$name"; }
# a search on the search head (or $2), CSV
spq(){ local c=${2:-$P-sh} f; f=$(mktemp); printf '%s' "$1" > "$f"
  rest "$c" POST /servicesNS/admin/tenx-for-splunk/search/jobs/export -d output_mode=csv -d earliest_time=0 \
    --data-urlencode latest_time=+10y -d preview=false --data-urlencode "search@$f"; rm -f "$f"; }
n1(){ spq "$1" | tail -n +2 | tr -dc '0-9'; }
mkindexes(){ for i in "$@"; do printf '[%s]\nhomePath = $SPLUNK_DB/%s/db\ncoldPath = $SPLUNK_DB/%s/colddb\nthawedPath = $SPLUNK_DB/%s/thaweddb\n\n' "$i" "$i" "$i" "$i"; done; }
mkapp(){ local d=$W/apps/$1; mkdir -p "$d/local" "$d/metadata"; printf '[install]\nstate = enabled\n[ui]\nis_visible = false\n' > "$d/local/app.conf"
  printf '[]\naccess = read : [ * ], write : [ admin ]\nexport = system\n' > "$d/metadata/local.meta"; }
# samples: <host>|<file>|<sourcetype>|<source>|<index suffix>
SAMPLES_SET=("dc1|win662.log|XmlWinEventLog|XmlWinEventLog:Security|win" "fs2|win4663.log|XmlWinEventLog|XmlWinEventLog:Security|win2"
  "fwa|fgt100k.log|fgt_log|/var/log/fortigate/fwa.log|fgt" "fwb|fgt239.log|fgt_log|/var/log/fortigate/fwb.log|fgt2")
INDEXES=$(for p in t m d; do for s in win win2 fgt fgt2; do printf 'hfm_%s_%s hfm_%sr_%s ' $p $s $p $s; done; done; echo hfm_fallback tenx_dml tenx_probe)

build(){
  mkdir -p "$W/secret" "$W/data" "$W/apps" "$W/opt/tenx/rfs" "$W/opt/tenx/compact/events" "$W/opt/tenx/compact/templates" \
    "$W/opt/tenx/state" "$W/opt/tenx/receiver"; chmod 700 "$W/secret"
  [ -s "$W/secret/admin.pw" ] || ( umask 077; python3 -c 'import secrets,string; a=string.ascii_letters+string.digits; print("Hm"+"".join(secrets.choice(a) for _ in range(20))+"!4")' > "$W/secret/admin.pw" )
  chmod 777 "$W/opt/tenx" "$W/opt/tenx/rfs" "$W/opt/tenx/compact" "$W/opt/tenx/compact/events" "$W/opt/tenx/compact/templates" "$W/opt/tenx/state"
  docker network inspect $NET >/dev/null 2>&1 || docker network create --subnet $SUB.0/24 $NET >/dev/null
  run(){ local n=$1 a=$2 img=$3 cpu=$4 mem=$5; shift 5; docker ps -a --format '{{.Names}}' | grep -qx "$n" && return 0
    SPLUNK_PASSWORD="$(pw)" docker run -d --name "$n" --hostname "$n" --network $NET --ip "$a" --cpus="$cpu" -m "$mem" -e SPLUNK_PASSWORD \
      -e SPLUNK_START_ARGS=--accept-license -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com -e TZ=UTC "$@" "$img" >/dev/null && log "$n created"; }
  run $P-idx $IDX "$SPLUNK" 2 6g; run $P-sh $SH "$SPLUNK" 2 6g; run $P-hf $HF "$SPLUNK" 2 6g -v "$W/opt/tenx:/opt/tenx"
  run $P-uf $UF "$UFIMG" 1.5 2g -v "$W/data:/data:ro"
  for c in $P-idx $P-sh $P-hf; do until docker logs "$c" 2>&1 | tail -50 | grep -q "PLAY RECAP"; do sleep 10; done; until up200 "$c"; do sleep 5; done; log "$c up"; done
  until docker logs $P-uf 2>&1 | tail -50 | grep -q "PLAY RECAP"; do sleep 10; done; log "$P-uf up"
}

config(){
  : "${PKG:?set PKG}"; : "${ADDONS:?set ADDONS}"; local A=$W/apps
  rm -rf "$A/pkg" "$A/ix"; mkdir -p "$A/pkg" "$A/ix"; tar -xzf "$PKG" -C "$A/pkg"
  # the _indexers package, by slim partition on a copy of the package, for the heavy forwarder
  docker exec -u root $P-hf sh -c 'rm -rf /tmp/slim && mkdir -p /tmp/slim/out'; docker cp "$PKG" $P-hf:/tmp/slim/tenx-for-splunk.tar.gz
  docker exec -u root $P-hf chown -R splunk:splunk /tmp/slim
  docker exec -u splunk $P-hf sh -c 'cd /tmp/slim && /opt/splunk/bin/slim partition tenx-for-splunk.tar.gz -o out' > "$W/res/slim.log" 2>&1
  docker cp $P-hf:/tmp/slim/out "$A/ix/" >/dev/null; tar -xzf "$(ls "$A"/ix/out/*_indexers*.tar.gz | head -1)" -C "$A/ix"
  local inner; inner=$(find "$A/ix" -maxdepth 3 -name '*.tar.gz' -path '*tenx-for-splunk*' ! -path '*/out/*' | head -1)
  [ -n "$inner" ] && tar -xzf "$inner" -C "$A/ix"
  local IXAPP; IXAPP=$(dirname "$(find "$A/ix" -path '*/default/app.conf' ! -path '*/out/*' | head -1)"); IXAPP=$(dirname "$IXAPP")
  grep -q '^\[tenx-record-unwrap\]' "$IXAPP/default/transforms.conf" && grep -q '^\[source::/opt/tenx/compact/events/...\]' "$IXAPP/default/props.conf" \
    && ok PASS "package: the _indexers package holds [tenx-record-unwrap] and its source stanza" || ok FAIL "package: unwrap missing from the _indexers package"
  # indexer: indexes only
  mkapp hfm_idx; mkindexes $INDEXES > "$A/hfm_idx/local/indexes.conf"; printf '[splunktcp://9997]\ndisabled = 0\n' > "$A/hfm_idx/local/inputs.conf"
  cp_app $P-idx "$A/hfm_idx" hfm_idx
  # search head: the whole app, add-ons, CIM; tenx-events reads the compact sourcetypes
  cp_app $P-sh "$A/pkg/tenx-for-splunk" tenx-for-splunk
  for a in Splunk_TA_windows Splunk_TA_fortinet_fortigate Splunk_SA_CIM; do cp_app $P-sh "$ADDONS/$a" $a; done
  docker exec -u splunk $P-sh sh -c 'mkdir -p /opt/splunk/etc/apps/tenx-for-splunk/local && printf "[tenx-events]\ndefinition = index=* (sourcetype::tenx_encoded OR tenx_compact_st::tenx_win OR tenx_compact_st::tenx_fgt)\n" > /opt/splunk/etc/apps/tenx-for-splunk/local/macros.conf'
  # heavy forwarder: the _indexers package, the add-ons, and hfm_hf: rig parsing of the sample files, the route, the
  # file destination, tcpout, the compact folders' monitors
  cp_app $P-hf "$IXAPP" tenx-for-splunk
  for a in Splunk_TA_windows Splunk_TA_fortinet_fortigate; do cp_app $P-hf "$ADDONS/$a" $a; done
  mkapp hfm_hf; local L=$A/hfm_hf/local
  cat > "$L/props.conf" <<'X'
# Rig parsing of the sample files, the same for both arms.
[XmlWinEventLog]
TIME_PREFIX = <TimeCreated SystemTime='
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%9NZ
MAX_TIMESTAMP_LOOKAHEAD = 40
TRUNCATE = 0
MAX_DAYS_AGO = 10951
TRANSFORMS-zzz_tenx = tenx_route_file

[fgt_log]
TIME_PREFIX = ^date=
TIME_FORMAT = %Y-%m-%d time=%H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 30
MAX_DAYS_AGO = 10951
TRANSFORMS-zzz_tenx = tenx_route_file
X
  cat > "$L/transforms.conf" <<'X'
# The docs' route, by index pattern; an event read back from the compact folder carries tenx_sourcetype and is never routed.
[tenx_route_file]
INGEST_EVAL = $pd:_destinationKey$=if(match(index, "^hfm_[tmd]_") AND isnull(tenx_sourcetype), "rfs:tenx", null())
X
  cat > "$L/outputs.conf" <<X
[tcpout]
defaultGroup = idx
indexAndForward = false

[tcpout:idx]
server = $IDX:9997
useACK = true

[rfs:tenx]
path = file:///opt/tenx/rfs
format = ndjson
compression = none
partitionBy = day, sourcetype
batchTimeout = 5
fs.timeBeforeClosingFileSecs = 30
X
  { printf '[splunktcp://9997]\ndisabled = 0\n'
    for d in t-wxml:tenx_encoded t-fgt:tenx_encoded m-wxml:tenx_win m-fgt:tenx_fgt d-fgt:tenx_encoded; do
      mkdir -p "$W/opt/tenx/compact/events/${d%%:*}"; chmod 777 "$W/opt/tenx/compact/events/${d%%:*}"
      printf '\n[monitor:///opt/tenx/compact/events/%s]\nsourcetype = %s\nindex = hfm_fallback\ncrcSalt = <SOURCE>\ndisabled = 0\n' "${d%%:*}" "${d#*:}"; done
    printf '\n[monitor:///opt/tenx/compact/templates]\nsourcetype = tenx_dml_raw_json\nindex = tenx_dml\ncrcSalt = <SOURCE>\ndisabled = 0\n'; } > "$L/inputs.conf"
  cp_app $P-hf "$A/hfm_hf" hfm_hf
  # universal forwarder: to the heavy forwarder
  mkdir -p "$A/hfm_uf/local"; printf '[install]\nstate = enabled\n' > "$A/hfm_uf/local/app.conf"
  printf '[tcpout]\ndefaultGroup = hf\n\n[tcpout:hf]\nserver = %s:9997\nuseACK = true\n' $HF > "$A/hfm_uf/local/outputs.conf"; : > "$A/hfm_uf/local/inputs.conf"
  cp_app $P-uf "$A/hfm_uf" hfm_uf
  for c in $P-idx $P-hf $P-sh; do restart $c; done; sp $P-uf restart >/dev/null 2>&1; log "$P-uf restarted"
  for c in $P-sh $P-hf; do P_=$(pw) docker exec -u splunk -e P_ $c sh -c '/opt/splunk/bin/splunk add search-server https://'$IDX':8089 -auth "admin:$P_" -remoteUsername admin -remotePassword "$P_"' 2>&1 | grep -v WARNING; done
  rest $P-hf POST /services/data/indexes -d name=tenx_probe -o /dev/null -w "tenx_probe on the heavy forwarder: %{http_code}\n"
  for c in $P-hf $P-sh; do echo "$c add-on inputs enabled: $(sp $c btool inputs list --debug | grep -E 'Splunk_TA_|Splunk_SA_CIM' | grep -cE 'disabled *= *(0|false)')"; done
  sp $P-hf btool props list 'source::/opt/tenx/compact/events/...' | head -3
  log config done
}

# Fluent Bit (two processes) and one Receiver per source, for a pass; mode opt (receiverOptimize) or map (cap files)
fluent(){
  local pass=$1 mode=$2 C=$W/fb/$1; mkdir -p "$C/in" "$C/back" "$W/opt/tenx/state/$pass"; chmod -R a+rX "$W/fb"; chmod 777 "$W/opt/tenx/state/$pass"
  printf '[PARSER]\n    Name    json\n    Format  json\n' > "$C/in/parsers.conf"
  tail_in(){ local name=$1 path=$2 port=$3; printf '\n[INPUT]\n    Name               tail\n    Path               %s\n    Tag                rfs.%s.*\n    Parser             json\n    Read_from_Head     true\n    Refresh_Interval   1\n    Buffer_Chunk_Size  64k\n    Buffer_Max_Size    4M\n    DB                 /opt/tenx/state/%s/tail_%s.db\n    Mem_Buf_Limit      16MB\n    storage.type       filesystem\n\n[OUTPUT]\n    Name         forward\n    Match        rfs.%s.*\n    Host         127.0.0.1\n    Port         %s\n    Retry_Limit  False\n' "$path" "$name" "$pass" "$name" "$name" "$port"; }
  { printf '[SERVICE]\n    Flush                      1\n    Parsers_File               /fluent-bit/etc/parsers.conf\n    HTTP_Server                On\n    HTTP_Port                  2020\n    storage.path               /opt/tenx/state/%s/storage-in\n    storage.sync               normal\n    storage.backlog.mem_limit  16M\n' "$pass"
    [ "$pass" = d ] || tail_in wxml '/opt/tenx/rfs/*/*/*/sourcetype=XmlWinEventLog/*.ndjson' 24224
    tail_in fgt '/opt/tenx/rfs/*/*/*/sourcetype=fortigate_*/*.ndjson,/opt/tenx/rfs/*/*/*/sourcetype=fgt_log/*.ndjson' 24226; } > "$C/in/fluent-bit.conf"
  file_out(){ printf '\n[OUTPUT]\n    Name         file\n    Match        %s\n    Path         %s\n%s    Format       plain\n    Mkdir        On\n    Retry_Limit  False\n' "$1" "$2" "${3:+    File         $3
}"; }
  { printf '[SERVICE]\n    Flush                      1\n    HTTP_Server                On\n    HTTP_Port                  2021\n    storage.path               /opt/tenx/state/%s/storage-back\n    storage.sync               normal\n    storage.backlog.mem_limit  16M\n\n[INPUT]\n    Name          forward\n    Listen        0.0.0.0\n    Port          24225\n    Tag_Prefix    tenx.\n    storage.type  filesystem\n' "$pass"
    [ "$pass" = d ] || file_out 'tenx.rfs.wxml.*' "/opt/tenx/compact/events/$pass-wxml" ""
    file_out 'tenx.rfs.fgt.*' "/opt/tenx/compact/events/$pass-fgt" ""
    file_out tenx.tenx-template /opt/tenx/compact/templates templates.ndjson; } > "$C/back/fluent-bit.conf"
  fluent_down
  docker run -d --name $P-fbback --hostname $P-fbback --network $NET --ip $FBIP --cpus=1 -m 1g -v "$C/back:/fluent-bit/etc:ro" \
    -v "$W/opt/tenx/state:/opt/tenx/state" -v "$W/opt/tenx/compact:/opt/tenx/compact" "$FB" >/dev/null && log "fbback up ($pass)"
  local ARGS="@run/input/forwarder/fluentbit @apps/receiver" R=$W/opt/tenx/receiver n port
  for nm in wxml:24224 fgt:24226; do n=${nm%:*}; port=${nm#*:}; [ "$pass" = d ] && [ $n = wxml ] && continue
    if [ "$mode" = opt ]; then
      docker run -d --name $P-rx-$n --network container:$P-fbback --cpus=1.5 -m 4g "$RX" $ARGS receiverOptimize true varMaxRecurIndexes 0 \
        timestampZone UTC timestampMaxPerObject 1 groupJoinLines false fluentbitInputPort $port fluentbitOutputHost 127.0.0.1 \
        fluentbitOutputPort 24225 fluentbitInputMessageField event >/dev/null
    else
      docker run -d --name $P-rx-$n --network container:$P-fbback --cpus=1.5 -m 4g \
        -v "$R/compact-config.yaml:/etc/tenx/config/pipelines/run/receive/compact/config.yaml:ro" -v "$R/$n:/opt/tenx/receiver/$n" "$RX" $ARGS \
        varMaxRecurIndexes 0 timestampZone UTC timestampMaxPerObject 1 groupJoinLines false fluentbitInputPort $port \
        fluentbitOutputHost 127.0.0.1 fluentbitOutputPort 24225 fluentbitInputMessageField event \
        compactReceiverLookupFile /opt/tenx/receiver/$n/compact-cap.csv >/dev/null
    fi && log "rx-$n up ($mode)"; done
  sleep 8
  docker run -d --name $P-fbin --network container:$P-fbback --cpus=1 -m 1g -v "$C/in:/fluent-bit/etc:ro" -v "$W/opt/tenx/state:/opt/tenx/state" \
    -v "$W/opt/tenx/rfs:/opt/tenx/rfs:ro" "$FB" >/dev/null && log "fbin up ($pass)"
}
fluent_down(){ for n in $P-fbin $P-rx-wxml $P-rx-fgt $P-fbback; do docker rm -f $n >/dev/null 2>&1; done; }

# the Universal Forwarder reads each sample twice for pass <p>: raw arm hfm_<p>r_<s>, routed arm hfm_<p>_<s>
uf_pass(){ local p=$1 f=$W/apps/hfm_uf/local/inputs.conf spec h file st src s arm ix
  for spec in "${SAMPLES_SET[@]}"; do IFS='|' read -r h file st src s <<< "$spec"
    for arm in r x; do mkdir -p "$W/data/$p/$arm/$h"; [ -f "$W/data/$p/$arm/$h/$file" ] || ln "$SAMPLES/$file" "$W/data/$p/$arm/$h/$file"
      [ $arm = r ] && ix=hfm_${p}r_$s || ix=hfm_${p}_$s
      printf '[monitor:///data/%s/%s/%s/%s]\nindex = %s\nsourcetype = %s\nhost = hfm-%s\nsource = %s\ncrcSalt = <SOURCE>\ndisabled = 0\n\n' \
        $p $arm "$h" "$file" $ix $st "$h" "$src" >> "$f"; done; done
  chmod -R a+rX "$W/data"; cp_app $P-uf "$W/apps/hfm_uf" hfm_uf; sp $P-uf restart >/dev/null 2>&1; log "uf reads pass $p"; }

# waits until each routed index holds as many events as its raw arm, and the count holds for 60 s
settle(){ local p=$1 prev="" cur s
  for i in $(seq 1 240); do cur=$(spq "| tstats count where index=hfm_${p}_* OR index=hfm_${p}r_* by index | sort index" | tail -n +2 | tr '\n' ' ')
    if [ -n "$cur" ] && [ "$cur" = "$prev" ] && python3 -c '
import sys; d=dict(x.split(",") for x in sys.argv[1].split())
r={k.replace("r_","_",1):v for k,v in d.items() if k.split("_")[1].endswith("r")}; c={k:v for k,v in d.items() if not k.split("_")[1].endswith("r")}
sys.exit(0 if r and r==c else 1)' "${cur//\"/}"; then log "pass $p settled: $cur"; return 0; fi
    prev=$cur; sleep 30; done; log "pass $p did not settle: $cur"; return 1; }

kv_load(){ spq "search index=tenx_dml sourcetype=tenx_dml_raw_json | sendalert tenx_dml_to_kv" >/dev/null
  local prev=-1 n; for i in $(seq 1 40); do n=$(n1 "| inputlookup tenx-dml-lookup | stats count"); [ "$n" = "$prev" ] && break; prev=$n; sleep 20; done
  log "KV store rows: $n (template records indexed: $(n1 "| tstats count where index=tenx_dml sourcetype=tenx_dml_raw_json"))"; }

# per event: text, _time to the microsecond, host, source and index (routed index named as its raw arm's)
keys(){ local p=$1 s=$2 mac=${3:-tx} line
  line=$(spq "| multisearch [search index=hfm_${p}r_$s | eval arm=\"raw\"] [search index=hfm_${p}_$s \`$mac\` | eval arm=\"10x\"] | eval ix=replace(index, \"^hfm_${p}r_\", \"hfm_${p}_\"), m=md5(_raw), k=md5(m.\"|\".strftime(_time, \"%s.%6N\").\"|\".host.\"|\".source.\"|\".ix) | stats count(eval(arm=\"raw\")) as r count(eval(arm=\"10x\")) as x by m k | eval keq=min(r,x) | stats sum(r) as r sum(x) as x sum(keq) as keq by m | eval teq=min(r,x) | stats sum(r) as raw sum(x) as tenx sum(teq) as text_equal sum(keq) as key_equal sum(eval(if(x>r,x-r,0))) as extra sum(eval(if(r>x,r-x,0))) as missing" | tail -1)
  IFS=, read -r raw tenx teq keq extra missing <<< "$line"
  [ -n "$raw" ] && [ "$raw" -gt 0 ] && [ "$raw" = "$tenx" ] && [ "$raw" = "$keq" ] && [ "$extra" = 0 ] && [ "$missing" = 0 ] && r=PASS || r=FAIL
  ok $r "keys pass $p $s ($mac): raw $raw, compact $tenx, text equal $teq, text+_time+host+source+index equal $keq, extra $extra, missing $missing"; }

# the files the heavy forwarder reports as finished reading
finished(){ rest $P-hf GET "/services/admin/inputstatus/TailingProcessor:FileStatus?output_mode=json" | python3 -c 'import json, sys
for path, status in json.load(sys.stdin)["entry"][0]["content"]["inputs"].items():
    if status.get("type") == "finished reading":
        print(path)'; }
hops(){ local p=$1
  { echo "== $(date -u +%T) hops, pass $p"
    echo "file destination lines with index hfm_${p}_*: $(sudo -n find "$W/opt/tenx/rfs" -name '*.ndjson' -exec cat {} + 2>/dev/null | grep -c "\"index\":\"hfm_${p}_")"
    echo "file destination lines with index hfm_${p}r_* (never routed): $(sudo -n find "$W/opt/tenx/rfs" -name '*.ndjson' -exec cat {} + 2>/dev/null | grep -c "\"index\":\"hfm_${p}r_")"
    echo "file destination folders of compact sourcetypes (a loop makes them): $(sudo -n find "$W/opt/tenx/rfs" -type d -name 'sourcetype=tenx*' | wc -l)"
    curl -s http://$FBIP:2020/api/v1/metrics | python3 -c 'import json,sys; m=json.load(sys.stdin); print("fluent bit in, tail records:", {k:v["records"] for k,v in m["input"].items()}); print("fluent bit in, to the Receivers (records, retried, dropped):", {k:(v["proc_records"],v.get("retried_records",0),v.get("dropped_records",0)) for k,v in m["output"].items()})'
    curl -s http://$FBIP:2021/api/v1/metrics | python3 -c 'import json,sys; m=json.load(sys.stdin); print("fluent bit back, from the Receivers:", {k:v["records"] for k,v in m["input"].items()}); print("fluent bit back, file outputs (records, retried, dropped):", {k:(v["proc_records"],v.get("retried_records",0),v.get("dropped_records",0)) for k,v in m["output"].items()})'
    for d in "$W"/opt/tenx/compact/events/$p-*; do echo "compact folder $(basename "$d"): $(find "$d" -type f | wc -l) files, $(cat "$d"/* 2>/dev/null | wc -l) lines"; done
    echo "compact folder templates/templates.ndjson: $(cat "$W/opt/tenx/compact/templates/templates.ndjson" 2>/dev/null | wc -l) lines; tenx_dml template records indexed: $(n1 "| tstats count where index=tenx_dml sourcetype=tenx_dml_raw_json")"
    echo "heavy forwarder, compact files finished reading: $(finished | grep -c '^/opt/tenx/compact/') of $(sudo -n find "$W/opt/tenx/compact" -type f | wc -l)"
    echo "indexed (search head), by index and sourcetype:"; spq "| tstats count where index=hfm_${p}_* OR index=hfm_${p}r_* OR index=hfm_fallback by index sourcetype | sort index sourcetype" | sed 's/^/  /'
    echo "events marked tenx_unwrap=failed: $(n1 "| tstats count where index=hfm_* tenx_unwrap=failed")"
  } | tee "$W/res/hops_$p.txt"
  local loop routed rawn compactn; loop=$(sudo -n find "$W/opt/tenx/rfs" -type d -name 'sourcetype=tenx*' | wc -l)
  routed=$(sudo -n find "$W/opt/tenx/rfs" -name '*.ndjson' -exec cat {} + 2>/dev/null | grep -c "\"index\":\"hfm_${p}_")
  rawn=$(n1 "| tstats count where index=hfm_${p}r_*"); compactn=$(n1 "| tstats count where index=hfm_${p}_*")
  [ "$loop" = 0 ] && [ "$routed" = "$rawn" ] && [ "$compactn" = "$rawn" ] && [ "$(n1 "| tstats count where index=hfm_fallback")" = "" -o "$(n1 "| tstats count where index=hfm_fallback")" = 0 ] && r=PASS || r=FAIL
  ok $r "hops pass $p: raw arm $rawn, file destination $routed, compact indexed $compactn, compact-sourcetype folders in the file destination $loop"; }

# waits until `tx` leaves no event of pass <p> compact: right after the KV store load, events of the last templates
# loaded stayed compact for a minute or two
expanded(){ local p=$1 n; for i in $(seq 1 40); do n=$(n1 "search index=hfm_${p}_* \`tx\` | where like(_raw, \"~%\") | stats count")
    [ "${n:-0}" = 0 ] && { log "pass $p: tx leaves no event compact"; return 0; }; log "pass $p: $n events still compact after tx"; sleep 15; done; return 1; }

pass_t(){ fluent t opt; uf_pass t; settle t; hops t; kv_load; check_t; }
check_t(){ expanded t
  spq "| tenxreplay" > "$W/res/replay_t.csv"
  for s in win win2 fgt fgt2; do keys t $s tx; done
  python3 "$HERE/fields.py" "$W" $SH t_win _rawmd5,host "search index=hfm_tr_win | eval _rawmd5=md5(_raw)" "search index=hfm_t_win \`txf\` | eval _rawmd5=md5(_raw)"
  python3 "$HERE/fields.py" "$W" $SH t_fgt _rawmd5,host "search index=hfm_tr_fgt | eval _rawmd5=md5(_raw)" "search index=hfm_t_fgt \`txf\` | eval _rawmd5=md5(_raw)" 0 +10y
}

maps(){ local T=$W/apps/pkg/tenx-for-splunk/bin/tenx_field_map.py R=$W/opt/tenx/receiver F=$W/fm
  mkdir -p "$F" "$R/wxml" "$R/fgt"; rm -rf "$F"/kv_*.json "$F"/fm_*
  [ -f "$R/compact-config.yaml" ] || { docker create --name $P-cfg "$RX" >/dev/null; docker cp $P-cfg:/etc/tenx/config/pipelines/run/receive/compact/config.yaml "$R/compact-config.shipped.yaml"; docker rm -f $P-cfg >/dev/null
    sed -e 's/^\(  fieldNames:\)$/\1 [templateHash]/' -e '/^    - \$=yield TenXEnv.get("symbolMessageField")$/d' "$R/compact-config.shipped.yaml" > "$R/compact-config.yaml"; }
  for n in wxml fgt; do printf 'pattern_hash,value\n' > "$R/$n/compact-cap.csv"; rm -f "$R/$n/compact-cap.csv.pending"; done; chmod -R a+rwX "$R"
  local n=0; while :; do rest $P-sh GET "/servicesNS/nobody/tenx-for-splunk/storage/collections/data/tenx_dml?output_mode=json&limit=2000&skip=$((n*2000))" > "$F/kv_$n.json"
    grep -q '"_key"' "$F/kv_$n.json" || { rm "$F/kv_$n.json"; break; }; n=$((n+1)); done
  local RECS; RECS=$(for f in "$F"/kv_*.json; do printf -- '--records %s ' "$f"; done)
  ( cd "$F" && python3 -I "$T" gen $RECS --target windows-security --rules lookup --addon "$ADDONS/Splunk_TA_windows" --leave-out SystemTime,EventRecordID \
      --app-name fm_win --cap-file "$R/wxml/compact-cap.csv" --out fm_win > "$W/res/gen_win.txt" 2>&1
    python3 -I "$T" gen $RECS --target fortigate --rules lookup --leave-out time --app-name fm_fgt --cap-file "$R/fgt/compact-cap.csv" --out fm_fgt > "$W/res/gen_fgt.txt" 2>&1 )
  grep -q '^REPORT-tenx_fgt_hash_vars' <(sed -n '/^\[tenx_fgt\]/,/^\[/p' "$F/fm_fgt/default/props.conf") && echo "fm_fgt: [tenx_fgt] holds the hash extraction"
  for m in fm_win fm_fgt; do cp_app $P-hf "$F/$m" $m; cp_app $P-hf "$F/${m}_floor" ${m}_floor; cp_app $P-sh "$F/$m" $m; done
  restart $P-hf; restart $P-sh
  export TENX_SPLUNKD_AUTH="admin:$(pw)"
  for m in win:wxml fgt:fgt; do python3 -I "$T" activate --app "$F/fm_${m%:*}" --cap-file "$R/${m#*:}/compact-cap.csv" --splunkd https://$HF:8089 \
      --probe-index tenx_probe --tls-verify off > "$W/res/activate_${m%:*}.txt" 2>&1; local rc=$?
    local cap; cap=$(($(wc -l < "$R/${m#*:}/compact-cap.csv")-1)); [ $rc = 0 ] && [ "$cap" -gt 0 ] && r=PASS || r=FAIL
    ok $r "activate fm_${m%:*} through the heavy forwarder's management port, no --probe-hec: rc $rc, $cap templates listed ($(tail -1 "$W/res/activate_${m%:*}.txt" | cut -c1-120))"; done
  unset TENX_SPLUNKD_AUTH
}

dmodel(){ local p=$1 s=$2 dm=$3 by=$4 a b
  q(){ spq "| tstats summariesonly=false fillnull_value=NULL count from datamodel=$dm where index=$1 by $by" | tail -n +2 | sort; }
  a=$(q hfm_${p}r_$s); b=$(q hfm_${p}_$s); local rows ev; rows=$(printf '%s\n' "$a" | grep -c .); ev=$(printf '%s\n' "$a" | awk -F, '{s+=$NF} END{print s+0}')
  [ "$rows" -gt 0 ] && [ "$a" = "$b" ] && r=PASS || r=FAIL
  ok $r "data model pass $p $s $dm by $by: raw $rows rows / $ev events, compact $(printf '%s\n' "$b" | grep -c .) rows, identical $( [ "$a" = "$b" ] && echo yes || echo no)"; }

pass_m(){ sudo -n find "$W/opt/tenx/rfs" -name '*.ndjson' -delete; fluent m map; uf_pass m; settle m; hops m; check_m; }
check_m(){ expanded m
  spq "| tenxreplay" > "$W/res/replay_m.csv"
  for s in win win2 fgt fgt2; do keys m $s tx; done
  # allowed: the field map limits the app's README lists for Windows XML (block fields not written, --leave-out SystemTime
  # and the add-on's event_time read from it, line breaks written as spaces, "-" for privilege_id and vendor_privilege)
  python3 "$HERE/fields.py" "$W" $SH m_win _rawmd5,host "search index=hfm_mr_win | eval _rawmd5=md5(_raw)" "search index=hfm_m_win \`txf\` | eval _rawmd5=md5(_raw)" 0 +10y \
    EventData_Xml,System_Props_Xml,SystemTime,event_time,PrivilegeList,UserAccountControl,privilege_id,vendor_privilege
  dmodel m win Authentication "Authentication.action Authentication.app Authentication.user Authentication.src Authentication.dest"
  dmodel m win Change.All_Changes "All_Changes.action All_Changes.object_category All_Changes.user All_Changes.object"
  dmodel m win Endpoint.Processes "Processes.process_name Processes.user Processes.dest"
  dmodel m fgt Network_Traffic "All_Traffic.action All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport"
  dmodel m fgt Network_Traffic "All_Traffic.app All_Traffic.src_zone All_Traffic.dest_zone All_Traffic.bytes_in All_Traffic.bytes_out"
  dmodel m fgt2 Network_Traffic "All_Traffic.action All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport"
  local left; left=$(n1 "search index=hfm_m_fgt2 \`tx\` | where isnotnull(tenx_expand_refused) OR like(_raw, \"~%\") | stats count")
  [ "${left:-0}" = 0 ] && r=PASS || r=FAIL; ok $r "pass m fgt2: events left compact or refused after tx: ${left:-0}"
  export TENX_SPLUNKD_AUTH="admin:$(pw)"
  python3 -I "$W/apps/pkg/tenx-for-splunk/bin/tenx_field_map.py" check --app "$W/fm/fm_fgt" --cap-file "$W/opt/tenx/receiver/fgt/compact-cap.csv" \
    --splunkd https://$HF:8089 --probe-index tenx_probe --tls-verify off --timeout 20 --poll 5 > "$W/res/check_fgt.txt" 2>&1; local rc=$?; unset TENX_SPLUNKD_AUTH
  # rc 1 with only no_match events (a value holding a control character, a README limit) still proves the map: check
  # names them and leaves the list as it is
  local nm; nm=$(grep -c 'no_match' "$W/res/check_fgt.txt")
  grep -q 'all indexed with their fields' "$W/res/check_fgt.txt" && { [ $rc = 0 ] || { [ $rc = 1 ] && [ "$nm" -gt 0 ] && ! grep -qE 'bad_row|no_table|no_row|emptied' "$W/res/check_fgt.txt"; }; } && r=PASS || r=FAIL
  ok $r "check fm_fgt through the heavy forwarder's management port: rc $rc; $(head -1 "$W/res/check_fgt.txt" | cut -c1-100); $(grep -o '[0-9]* compact events of tenx_fgt were indexed without their fields[^:]*' "$W/res/check_fgt.txt")"
}

# Receiver stop: a FortiGate file grows at RATE lines/s on the forwarder; the Receiver stops for OUT seconds
drill(){ local N=${N:-30000} RATE=${RATE:-200} OUT=${OUT:-300} L=$W/res/drill.log f=$W/apps/hfm_uf/local/inputs.conf
  sudo -n find "$W/opt/tenx/rfs" -name '*.ndjson' -delete; fluent d opt; : > "$L"
  for arm in r x; do mkdir -p "$W/data/d/$arm/fwd"; done; : > "$W/data/d/live.log"; ln -f "$W/data/d/live.log" "$W/data/d/r/fwd/live.log"; ln -f "$W/data/d/live.log" "$W/data/d/x/fwd/live.log"
  for arm in r x; do [ $arm = r ] && ix=hfm_dr_fgt || ix=hfm_d_fgt
    printf '[monitor:///data/d/%s/fwd/live.log]\nindex = %s\nsourcetype = fgt_log\nhost = hfm-fwd\nsource = /var/log/fortigate/fwd.log\ncrcSalt = <SOURCE>\ndisabled = 0\n\n' $arm $ix >> "$f"; done
  chmod -R a+rX "$W/data"; cp_app $P-uf "$W/apps/hfm_uf" hfm_uf; sp $P-uf restart >/dev/null 2>&1
  python3 "$HERE/writer.py" "$SAMPLES/fgt100k.log" "$W/data/d/live.log" $N $RATE 50000 >> "$L" 2>&1 & local wp=$!
  log "writer: $N lines at $RATE/s" | tee -a "$L"; sleep 60
  docker stop -t 30 $P-rx-fgt >/dev/null; log "Receiver stopped" | tee -a "$L"; sleep $OUT
  docker start $P-rx-fgt >/dev/null; local back; back=$(date +%s); log "Receiver started" | tee -a "$L"; wait $wp
  until [ "$(n1 "| tstats count where index=hfm_d_fgt")" = "$N" ] || [ $(( $(date +%s) - back )) -gt 3600 ]; do sleep 15; done
  log "compact reached $(n1 "| tstats count where index=hfm_d_fgt") of $N, $(( $(date +%s) - back )) s after the Receiver started" | tee -a "$L"
  sleep 60; hops d; expanded d; keys d fgt tx
  local retried; retried=$(curl -s http://$FBIP:2020/api/v1/metrics | python3 -c 'import json,sys; m=json.load(sys.stdin); print(sum(v.get("retried_records",0) for v in m["output"].values()), sum(v.get("dropped_records",0) for v in m["output"].values()))')
  log "fluent bit in, retried and dropped records: $retried" | tee -a "$L"; }

# the docs' clean-up job, run as root inside the heavy forwarder's container (where the folder and splunkd are)
clean(){ local before after files left bad
  before=$(n1 "| tstats count where index=hfm_* OR index=tenx_dml")
  docker cp "$HERE/compact-clean.sh" $P-hf:/tmp/compact-clean.sh >/dev/null
  pw | docker exec -i -u root $P-hf sh -c 'umask 077; printf "user = \"admin:%s\"\n" "$(cat)" > /opt/tenx/splunk-auth'
  sudo -n find "$W/opt/tenx/compact" -type f | sed "s#^$W##" | sort > "$W/res/clean_files_before.txt"; finished | sort > "$W/res/clean_finished_before.txt"
  local tl; tl=$(cat "$W/opt/tenx/compact/templates/templates.ndjson" 2>/dev/null | wc -l)
  docker exec -u root -e MINUTES=${MINUTES:-2} $P-hf sh /tmp/compact-clean.sh > "$W/res/clean.txt" 2>&1
  docker exec -u root $P-hf rm -f /opt/tenx/splunk-auth
  [ -f "$W/opt/tenx/compact/templates/templates.ndjson" ] || echo "$tl" >> "$W/res/templates_deleted.txt"
  sudo -n find "$W/opt/tenx/compact" -type f | sed "s#^$W##" | sort > "$W/res/clean_files_after.txt"
  files=$(wc -l < "$W/res/clean_files_before.txt"); left=$(wc -l < "$W/res/clean_files_after.txt")
  # a deleted file the heavy forwarder had not finished
  bad=$(comm -23 "$W/res/clean_files_before.txt" "$W/res/clean_files_after.txt" | comm -23 - "$W/res/clean_finished_before.txt" | wc -l)
  sleep 120; after=$(n1 "| tstats count where index=hfm_* OR index=tenx_dml")
  [ "$before" = "$after" ] && [ "$left" -lt "$files" ] && [ "$bad" = 0 ] && r=PASS || r=FAIL
  ok $r "clean-up: $files compact files before, $left after, $bad deleted unfinished; indexed events $before before, $after two minutes after"; }

# template records: the lines of every templates.ndjson the clean-up deleted, and of the current one, against tenx_dml
report(){ local written indexed; written=$(( $(awk '{s+=$1} END{print s+0}' "$W/res/templates_deleted.txt" 2>/dev/null || echo 0) + $(cat "$W/opt/tenx/compact/templates/templates.ndjson" 2>/dev/null | wc -l) ))
  indexed=$(n1 "| tstats count where index=tenx_dml sourcetype=tenx_dml_raw_json")
  [ "$written" = "$indexed" ] && r=PASS || r=FAIL; ok $r "template records: $written written to templates.ndjson (also after the clean-up deleted it), $indexed indexed in tenx_dml"
  echo "== summary"; cat "$SUM"; echo "PASS $(grep -c '^PASS' "$SUM"), FAIL $(grep -c '^FAIL' "$SUM")"; }
down(){ fluent_down; for c in $P-uf $P-hf $P-sh $P-idx; do docker rm -f -v $c >/dev/null 2>&1; done; docker network rm $NET >/dev/null 2>&1; log down; }

case "${1:-}" in
  build) build;; config) config;; pass) case "${2:-}" in t) pass_t;; m) pass_m;; esac;; check) case "${2:-}" in t) check_t;; m) check_m;; esac;;
  maps) maps;; drill) drill;; clean) clean;;
  report) report;; down) down;; *) sed -n 2,40p "$0";;
esac
