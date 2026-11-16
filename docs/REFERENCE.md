# Log10x App reference

The settings and internals behind the [README](../README.md).

## How It Works

A [compact event](https://doc.log10x.com/run/transform/#compact) carries a template hash and its variable values; the constant words live in the KV Store, and the app puts them back at search time. A word that exists only in a template is not in the index, so a plain keyword search over compact data finds the events where the word is a value and misses the others. To search by what the lines say, write the `tx` macro in front of the search terms, after the index and any metadata or time terms: ``index=app_logs `tx` error "payment failed"``. The words after it are ordinary SPL, applied to the expanded lines. Classic dashboards keep their panel SPL unchanged: `dashboard.js` routes each panel's search through the app's REST endpoint. An alert created in the app's **Compile Alert** view compiles once into a native saved search.

### Ingestion Flow

The [Receiver](https://doc.log10x.com/apps/receiver/) running in [Compact mode](https://doc.log10x.com/apps/receiver/compact/) [compacts](https://doc.log10x.com/run/transform/#compact) events at the edge, and Splunk ingests them at reduced size:

```
Receiver  -->  Ingest (HEC)  -->  KV Store (Templates)
                             -->  Index (compact events, metadata as indexed fields)
```

### Search Flow

Each path selects the compact events that can match, then [expands](https://doc.log10x.com/run/transform/#expand) them and applies the search to the original lines:

```
Search bar, Dashboard Studio, saved search:  `tx` macro  -->  prefilter (tenxprefilter)  --\
                                                                                           +-->  Expand  -->  Full results
Classic dashboard panel:  dashboard.js hook  -->  /tenx-search rewrite  -------------------/
```

On one laptop running Splunk 10.4.3, a `tx` search over 157,228 compact events returned in about 1.5 to 4 seconds, where the same search over the raw lines took under a second; the `| tx` command, which writes every event out itself, took two to five times as long as the macro.

Scheduled alerts run server-side, where the browser hook never fires. An alert created in the **Compile Alert** view, or through the `/tenx-alert` endpoint, is **compiled once at save time** into native SPL, a template hash prefilter plus the inflate macro, so the scheduler runs an ordinary saved search. This is handled by the `/tenx-alert` REST endpoint and the **Compile Alert** view (with a recompile pass that converts `| tx` and `| tenxsearch` alerts and refreshes prefilters as templates appear). See [SAVE_TIME_ALERTS.md](../SAVE_TIME_ALERTS.md).

## Receiver-side configuration

Start the Receiver with four arguments for any deployment that feeds this app.
`receiverOptimize true` makes it send events compact. The other three are options of the
Receiver's configuration; from engine 1.1.89 they can also follow the app on the command line,
which replaces the values the app's configuration sets. With the published image, beside a Fluent
Bit container:

```
docker run -d --name tenx-receiver --network container:<Fluent Bit container> log10x/edge-10x:1.1.180 \
  @run/input/forwarder/fluentbit @apps/receiver receiverOptimize true varMaxRecurIndexes 0 \
  timestampZone UTC timestampMaxPerObject 1
```

The first argument names the input module for the forwarder in use, here Fluent Bit; the
[forwarder inputs](https://doc.log10x.com/run/input/forwarder/) page lists the others.

The three options live in two files of the Receiver's config folder (`$TENX_CONFIG`, mounted at
`/etc/tenx/config` in the container image):

```yaml
# pipelines/run/template/config.yaml
var:
  maxRecurIndexes: 0

# pipelines/run/transform/timestamp/config.yaml
timestamp:
  maxPerObject: 1
  zone: UTC
```

With the shipped configuration, these arguments start the Receiver with these values.
Setting them in these files instead works as well.

### Back-references

**Set `varMaxRecurIndexes: 0`.** The app expands templates whose values all travel in the event.
The Receiver's [`varMaxRecurIndexes`](https://doc.log10x.com/run/template/#varmaxrecurindexes)
setting lets a template refer back to an earlier value (`$N`) instead. The setting applies to the
whole Receiver process. At 0, modeled compression is about half a percentage point lower on a
Kubernetes/OTel dataset, and every event expands exactly.

A Receiver that also feeds Elasticsearch applies the setting there too. The
[elasticsearch-plugin](https://github.com/log-10x/elasticsearch-plugin) decodes either form, and
that traffic compresses about half a point less.

### Timestamps

**Set `timestampZone: UTC`.**

A timestamp that carries no zone marker of its own, `2025-10-02 06:35:34,498`,
is only a time once something decides which zone it was written in. The Receiver
decides, and by default it uses the clock of the host it runs on. That choice is
not recorded in the compact event, so this app cannot recover it: the same line
compacted on a host in New York and on a host in UTC produces two different
events, and nothing downstream can tell them apart.

Pinning the Receiver to UTC makes that choice fixed and knowable, and this app's
inflate macro renders in UTC to match. Without it, expansion returns a time
shifted by the difference between the Receiver's host clock and UTC.

Timestamps that carry their own zone, anything ending in `Z` or an offset, are unaffected.

### One timestamp per event

**Set `maxPerObject: 1`** in the Receiver's timestamp configuration (`timestamp.maxPerObject`).

The Receiver records every timestamp it finds in an event as its own slot. This app stores one
timestamp format per template, so a template with two slots cannot render both. At `1` the first
timestamp keeps its slot and any later one becomes an ordinary variable whose text round-trips
unchanged.

### Store-time checks

Back-references, multi-timestamp templates and two different templates under one template hash
are detected when stored. Their events stay compact and carry `tenx_expand_refused` naming the
reason, `back-reference`, `multiple-timestamps` or `hash-conflict`, so every expanded line is the
original line. The Diagnostics dashboard lists every refused template. To clear a `hash-conflict`
after deciding which template is right, delete that key from the `tenx_dml` collection and run the
backfill search in Step 5. A Receiver's clock zone leaves no trace in the data, so
`timestampZone: UTC` is required rather than checked.

### Event time on compact events

A compact event's `_time` is the time in its original log line wherever the Receiver wrote
one, and the time Splunk indexed it otherwise. The Receiver writes a template's timestamp as
an epoch in the event's first variable, 13 digits for milliseconds or 19 for nanoseconds.
The `tenx-event-time` transform sets `_time` from a first variable of that shape while the
event is parsed, when it falls inside Splunk's own timestamp window: 2,000 days back and 2
days ahead, the defaults for `MAX_DAYS_AGO` and `MAX_DAYS_HENCE`. Any other first variable
keeps the index time. Searches and alerts over a time range select late and replayed logs by
the time in the line.

Measured on Splunk 9.4.15, 10.4.3 and 10.6.0.5, the same on each, with the OpenTelemetry demo
sample, 157,228 compact events: of the
134,668 whose original line carries a timestamp Splunk recognizes, 134,340 get that time as
`_time` to the second and 133,658 to the millisecond. The other 328 are lines without a full
date, which the Receiver and Splunk complete differently (glog lines carry no year, and three
lines carry only a time of day), and three lines where Splunk reads a number as a time. Where
a template's timestamp stops at whole seconds, `_time` does too.

The transform adds no licence-metered bytes: in the E21 licence run on Splunk 10.4.3 the
compact events metered exactly their raw text, 74,338,244 bytes, with it on. It is a parsing
setting, so it runs where compact events are parsed (see Step 1).

### Timestamps in expanded lines

Every timestamp renders in UTC for every viewer, at every hour of the year. Checked on Splunk
9.4.15, 10.4.3 and 10.6.0.5 with 10,708 events at 2,677 instants, among them every ten minutes for 14 hours either
side of the 2026 daylight-saving transitions, expanded by viewers in eight zones (UTC,
America/New_York, Europe/London, Australia/Sydney, Pacific/Chatham, America/Adak,
Asia/Kolkata, Etc/GMT-4): every line is the UTC text. A zone in the timestamp format prints
`+0000` or `UTC`.

## Analytics Dashboard

The Analytics dashboard finds compact events through the `tenx-events` macro.

| Panel | Description |
|--------|-------------|
| **Total Encoded Events** | Compact events indexed |
| **Active Templates** | Templates in the KV Store |
| **Compression Ratio** | Original size over compact size, on the latest 5,000 events |
| **Estimated Storage Savings** | Bytes saved and percentage reduction, on the latest 10,000 events |
| **Event Volume, Last 7 Days** | Compact events per hour |
| **Top 10 Templates by Usage** | Template hashes with the most events |
| **Inflation Success Rate** | Share of the latest 1,000 events that expand |

## Components

| Component | Description |
|-----------|-------------|
| **Search Hook** | `dashboard.js`, routing each classic dashboard panel's search to the Search Handler |
| **Search Handler** | `/tenx-search` REST endpoint rewriting a search for compact events |
| **tx Macro** | Written in front of a search to search compact events by what the lines say, from the search bar, Dashboard Studio, saved searches and alerts |
| **txf Macro** | `tx` with the search-time fields of the original sourcetype; see [Fields of the Original Sourcetype](tenx-for-splunk/README.md#fields-of-the-original-sourcetype-txf) |
| **tenxreplay Command** | Writes the replay macros `txf` runs, from the search head's props; run by the Rebuild Field Replay saved searches |
| **Field Map Tool** | `bin/tenx_field_map.py`: generates the app that writes compact events' original fields at index time; see [the Field Map](tenx-for-splunk/README.md#data-models-and-detections-the-field-map) |
| **tenxprefilter Command** | Run once per search by the `tx` macro; reads the search, looks up the templates that carry its words, and selects the compact events to expand |
| **tx and tenxsearch Commands** | `\| tx <search>` and `\| tenxsearch searchstring="..."`: generating commands that write every event out through Python, kept so saved searches written with them keep working |
| **tenxrecompile Command** | Recompiles every compiled alert so it picks up new templates |
| **Alert Compiler** | `/tenx-alert` REST endpoint compiling a search into a native scheduled alert at save time (with a recompile/migrate pass) |
| **Compile Alert View** | UI to compile, review, and recompile save-time alerts |
| **KV Store** | Template patterns for event reconstruction |
| **Inflate Macro** | SPL macro joining events with templates |
| **Consume KV Search** | Scheduled search storing new templates in the KV Store |
| **Backfill KV Search** | The same template load over 30 days, for templates indexed before the app was installed |
| **Recompile Compiled Alerts Search** | Runs `tenxrecompile` every 15 minutes |
| **Rebuild Field Replay Searches** | Run `tenxreplay` every hour, and every five minutes for sourcetypes not yet covered |
| **Field Map Events Without Fields Search** | Not scheduled; where a field map is installed, counts compact events indexed without their fields by index, sourcetype and reason |
| **Analytics Dashboard** | Compression and template metrics |
| **Diagnostics Dashboard** | Troubleshooting and verification tools |
