# Live gate: a heavy forwarder sends the compact events

Builds the arrangement of the README's "Receiver Beside a Heavy Forwarder" on throwaway containers and
checks it. A Universal Forwarder sends the samples to a heavy forwarder, which parses them and writes the
routed indexes to its ingest actions file destination. Fluent Bit and the Receivers, beside it, write the
compact events back as JSON lines under `/opt/tenx/compact/events/`. The heavy forwarder reads that folder
and sends the compact events to the indexer with its own tcpout, so no HTTP Event Collector is involved.
A separate search head searches the indexer.

```sh
export W=<work folder> PKG=<tenx-for-splunk package> SAMPLES=<samples folder> ADDONS=<add-ons folder>
for phase in build config "pass t" clean maps "pass m" drill clean report; do tests/live_hf_monitor/rig.sh $phase; done
tests/live_hf_monitor/rig.sh down
```

`SAMPLES` holds `win662.log` and `win4663.log` (rendered Windows Security XML events, one event after
another), `fgt100k.log` and `fgt239.log` (FortiGate key=value lines). `ADDONS` holds the unpacked
`Splunk_TA_windows`, `Splunk_TA_fortinet_fortigate` and `Splunk_SA_CIM`. The heavy forwarder takes the
package's `_indexers` part, made by `slim partition` as the README says; the search head the whole app.
Each sample is read twice with the same host and source, into a raw index and into a routed index, so the
routed index holds only the compact events.

Every check prints one line, PASS or FAIL, collected in `$W/res/summary.txt`:

- package: the `_indexers` package holds the unwrap rule and its `source::` stanza;
- hops, per pass: raw events, file destination lines, compact events indexed, and no folder of a compact
  sourcetype in the file destination (no loop); `hops_<pass>.txt` adds Fluent Bit's counts, the compact
  folder's files and lines, and the files the heavy forwarder has finished;
- keys: every event's text, `_time` to the microsecond, host, source and index, raw against compact
  through `tx`, on four hosts and three sources;
- fields: `txf` fields against raw, Windows and FortiGate (pass t), and through the Windows field map
  (pass m);
- activate and check of both field maps through the heavy forwarder's management port, without
  `--probe-hec`;
- data models through the field maps on the heavy forwarder: Authentication, Change and Endpoint
  Processes on Windows, Network_Traffic on FortiGate, raw against compact row for row;
- drill: a FortiGate file grows while its Receiver is stopped (`OUT` seconds, 300 by default); every
  event arrives once;
- clean-up: the job the README prints deletes only files the heavy forwarder has finished, and no
  indexed count changes.
