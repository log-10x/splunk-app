# Log10x App

Search-time expansion of 10x compact log events, for Splunk Enterprise 9.4 through 10.6. The package passes AppInspect's Splunk Cloud checks. 10x replaces repetitive patterns with compact template hashes, cutting stored volume while maintaining full searchability.

Compact events and their template records come from the Receiver, the Log10x engine running beside a log forwarder such as Fluent Bit or Fluentd; [deploying the Receiver](https://doc.log10x.com/apps/receiver/deploy/) is described in the Log10x documentation.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Fluent Bit Beside the Receiver](#fluent-bit-beside-the-receiver)
- [Fields of the Original Sourcetype: txf](#fields-of-the-original-sourcetype-txf)
- [Data Models and Detections: the Field Map](#data-models-and-detections-the-field-map)
- [Which Searches Change When a Source Moves](#which-searches-change-when-a-source-moves)
- [What to Install on Each Tier](#what-to-install-on-each-tier)
- [Getting Started](#getting-started)
- [Technical Reference](#technical-reference)
- [Troubleshooting](#troubleshooting)

---

## Overview

### What is 10x?

10x is a log optimization system that reduces log storage costs by identifying repetitive patterns in log events and replacing them with compact representations. Instead of storing full log lines repeatedly, 10x stores:

1. **Templates**: The static pattern structure with placeholders for variable data
2. **Encoded Events**: Compact representations containing only a hash reference and variable values

### What does the app do?

The app provides the infrastructure to:

1. **Receive** template definitions from the Receiver
2. **Store** parsed template data in a KV store for efficient lookup
3. **Inflate** compact events back to their original form at search time
4. **Search** compact data by what the lines say: the `tx` macro in front of an ordinary search, and classic dashboards unchanged

### Reduction Example

**Original log event:**
```
2024-01-15T10:30:45.123Z INFO [main] com.example.Service - Processing request for user john_doe with transaction id TX-789012
```

**10x compact form:**
```
~abc123def,1705314645123,john_doe,TX-789012
```

**Template stored in KV store:**
```
$(yyyy-MM-dd'T'HH:mm:ss.SSS'Z') INFO [main] com.example.Service - Processing request for user $ with transaction id $
```

At search time, the `tenx-inflate` macro reconstructs the original event by combining the template with the variable values.

Each template is sent to Splunk once and counted like any other data. Where new templates keep
arriving, as on a small or varied source, the template records can outweigh what compaction saves.
On a steady source the count of templates levels off.

---

## Architecture

### Data Flow

```
                                    +------------------+
                                    |   10x Receiver   |
                                    +--------+---------+
                                             |
                     +-----------------------+------------------------+
                     |                                                |
                     v                                                v
        +------------------------+                      +------------------------+
        | Templates (JSON)       |                      | Encoded Events         |
        | sourcetype:            |                      | sourcetype:            |
        | tenx_dml_raw_json       |                      | tenx_encoded            |
        +------------------------+                      +------------------------+
                     |                                                |
                     v                                                |
        +------------------------+                                    |
        | Saved Search           |                                    |
        | "Consume KV"           |                                    |
        | (runs every 5 min)     |                                    |
        +------------------------+                                    |
                     |                                                |
                     v                                                |
        +------------------------+                                    |
        | Alert Action           |                                    |
        | tenx_dml_to_kv.py       |                                    |
        +------------------------+                                    |
                     |                                                |
          +----------+----------+                                     |
          |                     |                                     |
          v                     v                                     |
+------------------+  +------------------+                            |
| KV Store         |  | tenx_dml_pure    |                            |
| (tenx_dml)       |  | (searchable)     |                            |
+------------------+  +------------------+                            |
          |                                                           |
          +---------------------------+-------------------------------+
                                      |
                                      v
                           +--------------------+
                           | Search Time        |
                           | `tenx-inflate`      |
                           | macro expansion    |
                           +--------------------+
                                      |
                                      v
                           +--------------------+
                           | Original Events    |
                           | Restored           |
                           +--------------------+
```

### Components

#### Sourcetypes

| Sourcetype | Purpose |
|------------|---------|
| `tenx_dml_raw_json` | Receives template definitions as JSON: `{"templateHash":"...", "template":"..."}` |
| `tenx_dml_pure` | Searchable copy of each template (hash + stripped pattern text). Written with `collect` as sourcetype `stash` and source `tenx_dml_pure`, which Splunk does not count against the licence; copies an install already holds keep sourcetype `tenx_dml_pure` |
| `tenx_encoded` | Encoded log events in format: `~<hash>,<var0>,<var1>,...`, or `~<hash>` for a template with no values |

#### KV Store Collection

The `tenx_dml` collection stores parsed template data with fields:

| Field | Type | Description |
|-------|------|-------------|
| `_key` | string | Template hash (primary key) |
| `pattern_hash` | string | Same as `_key` |
| `pattern` | string | Original template pattern |
| `pattern_parts` | array | Middle template segments (for mvzip reconstruction) |
| `part_0` | string | First template segment (before first variable) |
| `pattern_terminator` | string | Last template segment (after last variable) |
| `timestamp_format` | string | Splunk strftime format for timestamp reconstruction |
| `expand_unsafe` | string | Empty when the template can be expanded; otherwise the reason it cannot (`back-reference`, `multiple-timestamps`, `hash-conflict`), and the inflate macro leaves its events compact |
| `pattern_search` | string | Searchable text of the template: separators removed, line breaks as spaces |
| `search_copy` | string | `pending` until the searchable copy is written, then `written` |

#### Macros

| Macro | Purpose |
|-------|---------|
| `tenx-inflate` | Main inflation macro: reconstructs original events |
| `tenx-inflate-debug` | Same as above but keeps intermediate fields for debugging |
| `tenx-message(1)` | Utility macro to display messages in search results |
| `tx` | Written in front of a search: searches compact events by what the original lines say (see Usage) |
| `txf`, `txf(<sourcetype>)` | `tx` with the search-time fields of the original sourcetype (see [Fields of the Original Sourcetype](#fields-of-the-original-sourcetype-txf)) |
| `tenx-events` | Where the compact events are: the index and sourcetype `tx` and the dashboards read |
| `tenx-templates` | Where the searchable copies of the templates are, for `tx` |

#### Search Surfaces

| Surface | Purpose |
|---------|---------|
| `` `tx` <search> `` | Macro: searches compact events by what the original lines say, from the search bar, Dashboard Studio, saved searches and alerts (see Usage) |
| `tenxprefilter` | Generating command the `tx` macro runs once per search, in its subsearch, to select the compact events to expand; not typed |
| `\| tx <search>`, `\| tenxsearch searchstring="..."` | Generating commands that run a rewritten search and write every event out through Python; kept so saved searches written with them keep working |
| `appserver/static/dashboard.js` + `javascript/search/tenx_search_hook.js` | Loaded on every classic dashboard in an app that carries `dashboard.js`; routes panel searches through `/tenx-search` |
| `/tenx-search` REST endpoint | Rewrites a search and returns an ordinary job id; what the dashboard hook calls |

#### Saved Searches

| Saved search | Schedule | What it does |
|--------------|----------|--------------|
| Consume KV | every 5 minutes | Stores the template records indexed in the last seven minutes in the KV store |
| Backfill KV | not scheduled | The same load over 30 days, for templates indexed earlier |
| Recompile Compiled Alerts | every 15 minutes | Runs `tenxrecompile` so compiled alerts pick up new templates |
| Rebuild Field Replay | every hour | Runs `tenxreplay`, which writes the replay macros `txf` runs |
| Rebuild Field Replay When New | every 5 minutes | Runs `tenxreplay` for original sourcetypes not yet covered |
| Field Map Events Without Fields | not scheduled | Counts compact events indexed without their fields (`tenx_unmapped`) by index, sourcetype and reason, with index-time rule errors from `splunkd.log`; schedule it where a field map is installed |

#### Python Scripts

| Script | Purpose |
|--------|---------|
| `tenx_prefilter.py` | The `tenxprefilter` command the `tx` macro runs |
| `tenx_prefilter_parser.py` | Reads the words after `tx` as a search and builds the prefilter from them |
| `tenxsearch.py` | The `tenxsearch` generating command, and the search rewrite the `tx` command shares |
| `tx.py` | The `tx` generating command |
| `tenxrecompile.py` | The `tenxrecompile` command, run every 15 minutes by the Recompile Compiled Alerts saved search |
| `tenx_alert_recompile.py` | Recompiles managed alerts, each written back to its owner |
| `tenx_search_builder.py` | Compiles a user search into a search over compact events |
| `tenx_spl_parser.py` | Grammar and AST for the search terms the builder rewrites |
| `tenx_search_manager.py` | Search jobs and the template dictionary lookups |
| `tenx_alert_compiler.py` | Save-time compile of an alert into native SPL |
| `tenx_dml_to_kv.py` | Alert action that populates KV store from template JSON |
| `tenx_dml_builder.py` | Core logic for parsing templates into KV-storable format |
| `tenx_util.py` | Utility functions (REST client, logging, config loading) |
| `tenx_consts.py` | Default configuration constants |
| `tenx_kv_intf.py` | KV store interface (get/create entries) |
| `tenx_dml_intf.py` | DML sourcetype interface (submit events) |
| `tenxreplay.py` | The `tenxreplay` command, run by the Rebuild Field Replay saved searches: writes the replay macros `txf` runs |
| `tenx_replay_builder.py` | Turns the props of the original sourcetypes into the replay macros |
| `tenx_field_map.py` | The field map tool: `gen`, `verify`, `activate` and `check` (see [the Field Map](#data-models-and-detections-the-field-map)) |
| `tenx_search_report.py` | Says which saved searches, alerts and dashboard panels change when a source moves to compact events (see [Which Searches Change](#which-searches-change-when-a-source-moves)) |

---

## Installation

### Prerequisites

- Splunk Enterprise 9.4 through 10.6
- Python 3.9 or later, as shipped with those versions of Splunk
- Admin access to install apps

### Installation Steps

1. **Install the package file:**
   ```bash
   $SPLUNK_HOME/bin/splunk install app tenx-for-splunk-<version>.tar.gz
   ```

   In a shell without a Splunk login, add `-auth <user>:<password>`.

2. **Restart Splunk:**
   ```bash
   $SPLUNK_HOME/bin/splunk restart
   ```

3. **Verify installation:**
   - Navigate to Settings > Apps in Splunk Web
   - Confirm "Log10x App" appears in the app list

4. **Create the template index:**
   - Create an index named `tenx_dml` where events are stored: on a standalone instance
     `curl -k -u admin https://localhost:8089/services/data/indexes -d name=tenx_dml`, on an indexer
     cluster a `[tenx_dml]` stanza with `repFactor = auto` in an `indexes.conf` of the cluster
     bundle. Templates arrive there as `tenx_dml_raw_json` and count against the Splunk licence
     like any indexed event; their searchable copy, written there with `collect` (sourcetype
     `stash`, source `tenx_dml_pure`), does not. Compact events (`tenx_encoded`) go to any index.

5. **Point the dashboards at your compact index:** set the `tenx-events` macro, see
   [Pointing the Dashboards at Your Compact Events](#pointing-the-dashboards-at-your-compact-events).

6. **Load templates already indexed:** run the backfill search once, see
   [Loading Templates Indexed Earlier](#loading-templates-indexed-earlier).

### Directory Structure

```
tenx-for-splunk/
├── app.manifest                 # Workloads, for slim partition
├── appserver/static/            # dashboard.js, the search hook, the Compile Alert script
├── bin/                         # Python scripts, see Python Scripts above, the field map tool among them
├── default/
│   ├── alert_actions.conf       # Alert action definition
│   ├── app.conf                 # App metadata
│   ├── collections.conf         # KV store schema
│   ├── commands.conf            # The tenxprefilter, tx, tenxsearch, tenxrecompile and tenxreplay commands
│   ├── macros.conf              # SPL macros, including tx
│   ├── props.conf               # Sourcetype definitions
│   ├── restmap.conf, web.conf   # The /tenx-search and /tenx-alert endpoints
│   ├── savedsearches.conf       # Consume KV, Backfill KV, Recompile Compiled Alerts, Rebuild Field Replay,
│   │                            # Rebuild Field Replay When New, Field Map Events Without Fields
│   ├── searchbnf.conf, server.conf  # Command help; tenx_config and tenx_replay replicated in a search head cluster
│   ├── tenx_config.conf         # App configuration
│   ├── transforms.conf          # Field extractions and lookups
│   └── data/ui/                 # Dashboards and navigation
├── lib/                         # splunklib and parsimonious, see THIRD_PARTY_NOTICES
├── metadata/
│   └── default.meta             # Permissions
├── README/                      # alert_actions.conf.spec, savedsearches.conf.spec,
│                                # tenx_config.conf.spec, tenx_replay.conf.spec
├── static/                      # App icons
├── LICENSE
└── THIRD_PARTY_NOTICES
```

---

## Configuration

### Main Configuration (tenx_config.conf)

Located at `$SPLUNK_HOME/etc/apps/tenx-for-splunk/default/tenx_config.conf`:

```ini
[config]
# Index for processed template data
dest_dml_index = tenx_dml

# Sourcetype for processed templates
dml_source_type = tenx_dml_pure

# KV store collection name
collection_name = tenx_dml

# Placeholder for timestamp in templates
timestamp_placeholder = __TENX_TS__

# Character separating variables in templates
variable_separator = $
```

### Modifying the Saved Search Schedule

The "Consume KV" saved search runs every 5 minutes by default. To adjust:

1. Navigate to Settings > Searches, reports, and alerts
2. Find "Consume KV" in the Log10x App
3. Edit the cron schedule as needed

Or modify `savedsearches.conf`:

```ini
[Consume KV]
cron_schedule = */5 * * * *
search = index=tenx_dml sourcetype=tenx_dml_raw_json _index_earliest=-7m _index_latest=now
dispatch.earliest_time = -24h
dispatch.latest_time = now
```

Keep the index-time window (`_index_earliest`) wider than the interval, or a template that
arrives between two runs is never stored.

### Loading Templates Indexed Earlier

Consume KV stores templates as they arrive. Templates indexed before the app was installed,
or while Consume KV was disabled or failing, are loaded by running this search once, as an
admin or power user, after installing and after any outage of Consume KV:

```spl
index=tenx_dml sourcetype=tenx_dml_raw_json earliest=-30d | sendalert tenx_dml_to_kv
```

Widen `earliest` to reach older templates. Running it again is safe: templates already
stored are kept, and their records are brought up to date when this version of the app
derives them differently. The **Backfill KV** saved search holds the same search; the **Run**
button does not fire its alert action, so run the search above. To load every template
record ever indexed, use `earliest=0`.

### Adding Custom Sourcetypes for Encoded Events

To use 10x with custom sourcetypes, add to `props.conf`:

```ini
[my_custom_sourcetype]
REPORT-tenx = tenx-hash-vars-extraction
```

This applies the field extraction that parses compact events into `tenx_hash`, `tenx_var_0`, and `tenx_vars` fields.

### Pointing the Dashboards at Your Compact Events

The app's Analytics and Diagnostics dashboards read the `tenx-events` macro, and every `tx`
and `txf` search starts with it, so it limits what they read as well. Its default,
`index=* sourcetype::tenx_encoded`, finds the app's sourcetype in every index that can be
searched. Set it to the compact index, and add any custom sourcetype, under **Settings >
Advanced search > Search macros**. Write each sourcetype in the indexed form `sourcetype::`:
beside the prefilter `tx` adds to this clause, Splunk dropped some events matched with
`sourcetype=`. A field map's events are named with `tenx_compact_st::` (see the field map):

```spl
index=my_compact_index (sourcetype::tenx_encoded OR sourcetype::my_custom_sourcetype)
```

Several compact indexes, one of them with a field map:

```spl
(index=app_compact OR index=win_compact) (sourcetype::tenx_encoded OR tenx_compact_st::tenx_win)
```

Naming the index makes every panel faster.

---

## Usage

### Searching Compact Events

A compact event holds a template hash and the event's variable values; the constant words
live in the KV Store. A word that exists only in a template is not in the index, so a plain
keyword search over compact data finds the events where the word is a value and misses the
others. Search compact data with the `tx` macro.

**The `tx` macro**, in the search bar, Dashboard Studio panels, saved searches and alerts.
Write it in front of the search terms, after the index and any metadata or time terms:

```spl
index=myindex earliest=-4h `tx` "payment failed" NOT retry status=500 | stats count by host
```

The words after `tx` are ordinary SPL, applied to the expanded lines. Phrases,
`field=value`, `field IN (...)`, wildcards at the start or end of a word, `NOT`, `OR`, `AND`
and parentheses behave as on the original data, with Splunk's precedence. The fields
are the ones Splunk extracts from the original lines, key=value pairs and JSON alike.

Under `NOT` through the `tx` and `txf` macros, two kinds of word can return fewer events than on
the original lines: a wildcard inside a word (`Se*Privilege`), and `TERM()` of part of a longer
term (`TERM(10.2.236.94)` inside `client_ip=10.2.236.94`). Outside `NOT`, both match as on the
original lines. Under `NOT` in `| tx`, the same words give the exact opposite of the word, which
can be more events than Splunk's own `NOT` returns on the original lines. `TERM()` of text that
holds a major breaker, outside `NOT`, and `NOT CASE()` can return more events than on the original
lines, never fewer. Under `NOT` through the macros, such a `TERM()` can return fewer.
Searching an IP address, a hostname or an ID works the same way: the words go after `tx`,
whether they are values or template text.

**Classic dashboards.** `dashboard.js` loads on every classic dashboard in the app that
carries it and routes the panel's search through the app's REST endpoint. Panels keep
their SPL. To cover another app's dashboards, copy the file into that app's
`appserver/static/` and restart.

**Rules.**

- Time modifiers (`earliest=`, `latest=`) go before `tx`. After it they would match no
  event, so the search stops with a message saying so.
- A search word after `tx` with a comma outside quotes, such as `4625,` in `4625, 4624`, is
  matched literally by Splunk, so the search stops with a message. Remove the comma, or put the
  text in quotes. The commas of an `IN (...)` list do not stop it.
- The index, the compact sourcetype, host and the forwarder's indexed fields narrow what is read when
  they come before `tx`. After it they filter the expanded events, which gives the same
  result more slowly.
- The sourcetype before or after `tx` is the compact sourcetype (`sourcetype=tenx_encoded`); each
  event's original sourcetype is in the field `tenx_sourcetype`. To search by the original
  sourcetype, write `sourcetype=<sourcetype>` after `txf`, which gives each event its original
  sourcetype and its add-on's fields. `tenx_sourcetype=<sourcetype>` before `tx` selects the same
  events with only the fields Splunk extracts from the event's text, so a field an add-on defines
  matches nothing there. A search that names the original sourcetype in place of the compact one
  stops with a message saying so. Splunk shows the first 256 characters of that message, which says
  first what to write; it is whole when it names one sourcetype of up to 21 characters.
- `tx` inside another subsearch (`append`, `join`) or wrapped in another macro cannot read
  its own words. It then expands every compact event in range and applies the words after,
  with a warning: the same result, more slowly.
- A compact event is the event the Receiver formed. Lines without a timestamp of their
  own, such as the lines of a stack trace, join the line before them, so a stack trace is
  one event, a count counts events, and words joined with AND can match on different lines
  of one event.

When `tx` or `txf` stops a search, the search fails with a message. The search bar, dashboard panels
and Jobs show it; a REST job holds it (on Splunk 10.0 through 10.6 the job also ends FAILED), and a
oneshot job returns it. The REST export endpoint returns it with `output_mode=xml`; with `csv`, and
on Splunk 10.4 and 10.6 with `json`, it returns HTTP 200 and an empty body, as Splunk does for any
search that fails while running, so treat an empty export as a failure. A scheduled alert that stops
does not fire, and its job holds the message: on Splunk 9.4 the job ends DONE and the scheduler log
records the run as a success with no results; on 10.4 and 10.6 the job ends FAILED and `splunkd.log`
holds the message. `txf(<sourcetype>)` for a sourcetype without a field
replay is refused before the search runs, on every path. A saved search with such a macro cannot be
saved, and one whose replay is removed later is skipped, with the message in the scheduler log.

**How `tx` chooses the events to expand.** Its subsearch runs `tenxprefilter` once per
search. The command reads the search's own text, takes the words after `tx`, finds which
templates carry each word, and selects the compact events that carry each word as a value
or through their template. Templates are read from the KV store the expansion uses. A word a
rendered timestamp could print, a word with a character outside a-z and 0-9, and a word carried
by more than 5,000 templates select nothing on their own, and a `NOT`, a field comparison, or an
`OR` with any of these selects every event in range. A run of digits narrows unless a stored
template's timestamp could print it (a year, two digits of a time, a fraction of that length).
The search after `tx` then applies the full terms, so the selection may be wider than
the result, never narrower.

**The `tx` and `tenxsearch` commands.** `| tx index=myindex sourcetype=tenx_encoded error`
and `| tenxsearch searchstring="..."` run a rewritten search and write every event out
through Python, which is several times slower than the macro. They are kept so saved
searches written with them keep working. The search they run must name the compact sourcetype,
`sourcetype=tenx_encoded`. Without it the command stops and says so.

**Search behavior.**

- Without `tx`, a keyword search over compact data returns only the events where the
  word is a value, and a search with no keywords returns compact `~hash,...` rows. Keep
  compact indexes out of default index sets and name them in searches.
- A template appears in the dictionary when the Consume KV search stores it, every five
  minutes. Until then its events stay compact, and a search for a word of that template does
  not select them.

**Speed.** On one laptop running Splunk 10.4.3, a `tx` search over 157,228 compact events
returned in about 1.5 to 4 seconds, where the same search over the raw lines took under a
second. About 0.3 seconds of each is the `tenxprefilter` command and about 0.4 seconds is
Splunk starting it. The `| tx` command, which writes every event out itself, took two to five
times as long as the macro.

### Basic Expansion

Search compact events and expand them:

```spl
index=myindex sourcetype=tenx_encoded
| `tenx-inflate`
```

### Debugging Expansion

Keep intermediate fields to troubleshoot issues:

```spl
index=myindex sourcetype=tenx_encoded
| `tenx-inflate-debug`
| table tenx_hash, tenx_var_0, tenx_vars, tenx_log_parts, _raw
```

### Filtering Before Expansion

Apply filters on compact data before expanding (more efficient):

```spl
index=myindex sourcetype=tenx_encoded tenx_hash="abc123*"
| `tenx-inflate`
```

### Search After Expansion

Search for specific content after expansion:

```spl
index=myindex sourcetype=tenx_encoded
| `tenx-inflate`
| search "error" OR "exception"
```

### View Template Definitions

Check what templates are in the KV store:

```spl
| inputlookup tenx-dml-lookup
| table _key, pattern, timestamp_format
```

### Verify Encoded Event Extraction

Check that field extraction is working:

```spl
index=myindex sourcetype=tenx_encoded
| head 10
| table _raw, tenx_hash, tenx_var_0, tenx_vars
```

---

## Fluent Bit Beside the Receiver

Fluent Bit runs as two processes beside the Receiver, each in its own container with its own buffer
folder: the first reads the logs and hands each record to the Receiver, and the second takes the
Receiver's events back and sends them to Splunk's HTTP Event Collector (HEC). The Receiver and the
second process share the first one's network:

```sh
docker run -d --name tenx-fluentbit-in --network <network> \
  -v <fluent-bit-in.conf>:/fluent-bit/etc/fluent-bit.conf:ro -v <log folder>:/logs fluent/fluent-bit:5.1.5
docker run -d --name tenx-receiver --network container:tenx-fluentbit-in log10x/edge-10x:1.1.181 \
  @run/input/forwarder/fluentbit @apps/receiver receiverOptimize true varMaxRecurIndexes 0 \
  timestampZone UTC timestampMaxPerObject 1 groupJoinLines false
docker run -d --name tenx-fluentbit-back --network container:tenx-fluentbit-in --env-file <env file> \
  -v <fluent-bit-back.conf>:/fluent-bit/etc/fluent-bit.conf:ro -v <log folder>:/logs fluent/fluent-bit:5.1.5
```

`<network>` is a Docker network from which the HEC is reachable. The env file sets
`HEC_TOKEN=<HEC token>`, for a token that may write to `tenx_dml` and the compact index. The Receiver
and the second process run in the first one's network, so restart them after each restart of the
first. With `Retry_Limit False`, Fluent Bit keeps the records it reads in the meantime and sends them
when the Receiver is back.

The first process, `fluent-bit-in.conf`, with one `tail` input per log file:

```
[SERVICE]
    storage.path      /logs/flb-storage

[INPUT]
    Name              tail
    Path              /logs/<log file>
    DB                /logs/<log file>.db
    Tag               src.app
    Read_from_Head    true
    storage.type      filesystem

[OUTPUT]
    Name              forward
    Match             src.*
    Host              127.0.0.1
    Port              24224
    Retry_Limit       False
```

The second process, `fluent-bit-back.conf`: the template records go to `tenx_dml`, and each source's
compact events to the compact index.

```
[SERVICE]
    storage.path      /logs/flb-storage-back
    HTTP_Port         2021

[INPUT]
    Name              forward
    Listen            0.0.0.0
    Port              24225
    Tag_Prefix        tenx.
    storage.type      filesystem

[OUTPUT]
    Name              splunk
    Match             tenx.tenx-template
    Host              <HEC host>
    Port              8088
    Splunk_Token      ${HEC_TOKEN}
    TLS               On
    event_index       tenx_dml
    event_source      fluent-bit-tenx
    event_sourcetype  tenx_dml_raw_json
    Retry_Limit       False

[OUTPUT]
    Name              splunk
    Match             tenx.src.app
    Host              <HEC host>
    Port              8088
    Splunk_Token      ${HEC_TOKEN}
    TLS               On
    event_index       <compact index>
    event_sourcetype  tenx_encoded
    event_key         $log
    Retry_Limit       False
```

A multi-line source takes a multiline parser with `flush_timeout 30000` on its `tail` input, as the
Windows sources below do. Every `rewrite_tag` filter takes `Emitter_Storage.type filesystem` and
`Emitter_Mem_Buf_Limit 0`. Leave these unset: `storage.pause_on_chunks_overlimit`, `rate_gate`, and
memory storage with `Mem_Buf_Limit`, on a `tail` input; `Mem_Buf_Limit` and any pause option on the
second process's `forward` input; `storage.total_limit_size` on any output.

## Fields of the Original Sourcetype: `txf`

`tx` gives an expanded event the fields Splunk extracts from its text. The `txf` macro also
applies the search-time knowledge of the event's original sourcetype, as its add-on defines it:
field extractions, aliases, calculated fields, lookups, event types and tags. It is written where
`tx` goes:

```spl
index=wineventlog `txf` tag=authentication action=failure
index=wineventlog `txf(XmlWinEventLog)` EventCode=4625 | stats count by user
```

`txf(<sourcetype>)` applies the rules of that one sourcetype and starts faster. `txf` applies the
rules of every original sourcetype the app has recorded in the compact indexes.

A field comparison after `txf` reads every compact event in range. When the value is written in the
event (an event code, a user name), write it as a word too (`EventCode=4625 4625`): the same events,
read from those holding it. With the Windows add-on, a comparison on a Windows field does not narrow
the search, because the add-on computes or renames those fields; write the value as a word too, as
above.

To set it up:

1. Give every compact event the indexed field `tenx_sourcetype` with its original sourcetype: in
   the HEC event's `fields`, for example `"fields": {"tenx_sourcetype": "XmlWinEventLog"}`, or with
   `_meta = tenx_sourcetype::XmlWinEventLog` in the `inputs.conf` stanza that reads a compact file.
   With Fluent Bit as in [Fluent Bit Beside the Receiver](#fluent-bit-beside-the-receiver), the
   events the Receiver sends back arrive on the second process's `forward` input with
   `Tag_Prefix tenx.`; for each source, a `modify` filter there adds the field and the `splunk`
   output sends it as an indexed field:

   ```
   [FILTER]
       Name    modify
       Match   tenx.<tag of the source>
       Add     tenx_sourcetype XmlWinEventLog

   [OUTPUT]
       Name              splunk
       Match             tenx.<tag of the source>
       Host              <HEC host>
       Port              8088
       Splunk_Token      ${HEC_TOKEN}
       TLS               On
       event_index       <compact index>
       event_sourcetype  tenx_encoded
       event_source      XmlWinEventLog:Security
       event_key         $log
       event_field       tenx_sourcetype $tenx_sourcetype
       Retry_Limit       False
   ```

   The compact events must carry the source the add-on expects, as the raw events would: the
   Windows add-on selects Security events by the source `XmlWinEventLog:Security` and sets its CIM
   fields under that source, hence `event_source`. The AWS add-on sets its CloudTrail rules on the
   sourcetype `aws:cloudtrail`, so CloudTrail events need no particular source.

   Add `TLS.Verify Off` for an HTTP Event Collector with Splunk's default self-signed certificate.
   Match each source's own tag, not `tenx.*`: the Receiver also sends its status record, tagged
   `tenx.tenx-stdout`, which an output matching `tenx.*` indexes as a compact event at every start.

   Windows Security events reach the Receiver as the rendered XML of each event, one event per
   record: the form the Windows add-on's `XmlWinEventLog` sourcetype holds. For events in files,
   Fluent Bit's `tail` input with a multiline parser that starts a record at `<Event` gives that
   form, the parser in a parsers file named by `Parsers_File` in `[SERVICE]`. Events read from the
   Windows event log itself, by a Universal Forwarder's `WinEventLog` input or Fluent Bit's
   `winevtlog` input, are outside these steps. Set `storage.path` in `[SERVICE]` as well and
   `storage.type filesystem` on the input, so a record the parser completes while the input is paused
   waits on disk:

   ```
   [MULTILINE_PARSER]
       name          win_xml
       type          regex
       flush_timeout 30000
       rule          "start_state"  "/^<Event/"       "cont"
       rule          "cont"         "/^(?!<Event)/"   "cont"

   [INPUT]
       Name              tail
       Path              <file of rendered Windows Security events>
       Tag               src.win
       Read_from_Head    true
       DB                <file where Fluent Bit records how far it has read>
       Buffer_Chunk_Size 64k
       Buffer_Max_Size   2M
       multiline.parser  win_xml
       storage.type      filesystem
   ```

   The `DB` file keeps Fluent Bit's place in each file it reads, so after a restart it reads on
   from there instead of from the start of the file.
2. Install the add-on of each original sourcetype on the search head, as for raw data.
3. Run `| tenxreplay` once, or wait for the **Rebuild Field Replay When New** saved search, which
   runs every five minutes. It writes the replay macros from the search head's own props for the
   original sourcetypes found in the compact indexes. **Rebuild Field Replay** rewrites them every
   hour. Its output lists, per original sourcetype, the indexed fields kept on replayed events
   (`kept_indexed_fields`): those fields.conf declares with `INDEXED = true`, and those found on
   the 1,000 most recent compact events or on the most recent event of each index, host, source
   and sourcetype. An indexed field that only older events of a sender carry is kept once
   fields.conf declares it. The output may also warn that some fields set when compact events are
   read take their names from the data and are not cleared on replayed events: names that a
   key=value or JSON extraction takes from the text cannot be listed in advance.

A compact event without `tenx_sourcetype` is expanded and extracted exactly as by `tx`.

Checked with Splunk Add-on for Microsoft Windows 12.0.0, Splunk Add-on for AWS 8.3.1 and the Fortinet FortiGate Add-on for Splunk 1.6.10 against the same events indexed raw; the results are in the [listing's checks](https://github.com/log-10x/splunk-app/blob/main/splunkbase/LISTING.md#checks-run-on-this-package).

With the Windows add-on's index-time XML profile (`XML_INDEXED_EXTRACTIONS_PIPELINE = typing`), raw
events also carry fields Splunk indexes from the XML. `txf` gives the add-on's search-time fields,
so three fields that depend on that indexing (`xmlns`, `vendor_privilege`, `privilege_id`) are not
on expanded events. `linecount` and `punct` are computed by Splunk from the compact text it indexes,
so on expanded events they differ from the raw event's.

With the Receiver on each host, before the heavy forwarder, the heavy forwarder's index-time rules
do not apply to compact events: index overrides, masks (`SEDCMD`, `_raw` rewrites), `nullQueue`
filters and index-time fields. A value such a mask hides on raw events is readable after expansion,
and events such a filter drops are indexed and counted against the license. To keep these rules,
[place the Receiver after the heavy forwarder's parsing](#receiver-beside-a-heavy-forwarder).

Through `txf`, a field whose name holds `*`, such as the JSON key `"a*"`, has each value twice on an
event the sender passed whole; on a compact event it is as on the raw event.

For FortiGate, the sender sets `tenx_sourcetype` to `fortigate_traffic`, `fortigate_utm`,
`fortigate_event` or `fortigate_anomaly` by the line's `type=`.

A compact event's `_time` is the first timestamp the Receiver found in the line. In a CloudTrail
record that can be `userIdentity.sessionContext.attributes.creationDate`, which comes before
`eventTime`. A CloudTrail field map built with `--time-props` (below) gives every compact
CloudTrail event the raw event's `_time`.

A FortiGate line has its date and time in two fields, `date=` and `time=`. The Receiver reads the
time and supplies the date, so a compact FortiGate event's `_time` can fall on another day. A
FortiGate field map (below) gives every compact FortiGate event the raw event's `_time`.

A timestamp without a year takes its year from the time the event is processed, so a replayed or
backfilled file from an earlier year gets the wrong year. Splunk guesses the year for such lines
too, and the two guesses can differ.

## Data Models and Detections: the Field Map

Needs the Receiver at release 1.1.181 or later.

Data models, their accelerations, `tstats` and saved searches that do not use `tx` read the
fields Splunk stored with an event. The field map writes a compact event's original fields while
it is indexed, so these searches read them. With a field map, the index is larger than raw on disk, by
about 10% to 70% depending on the source, while license goes down; without one, the index is smaller
than raw.

Put field terms before the macro (`` index=wineventlog EventCode=4625 `txf(XmlWinEventLog)` ``) and run
statistics, time charts and detections without it: Splunk answers from indexed fields. Use `tx` for
words.

`tenx_field_map.py`, in the app's `bin` folder, generates a Splunk app for one compact sourcetype.
For each template it holds one row of a lookup file; one static index-time rule reads the row and
writes the original event's fields as indexed fields, then renames the event to its original
sourcetype. The add-on's search-time rules then run on the event as on the raw one, except rules
that read the event's text instead of a field. For the Windows add-on, `--addon` in step 4 supplies
those.

A field map covers the templates stored when it is generated. The steps below are for Windows
Security; CloudTrail and FortiGate follow them. Steps 1, 6 and 7 keep the Receiver from compacting
the events of a template before its fields can be written; they were measured with the Windows,
CloudTrail and FortiGate maps, each through its own Receiver.

A field map has its own Receiver and its own cap file. Two maps of one target, for two fleets, each
take their own `--sourcetype` and `--app-name` as well: every name the tool writes follows the
compact sourcetype, so the two apps can be installed side by side. Send the mapped source, and only
that source, through that Receiver: with the cap list on, an event of any template that is not listed
arrives whole. A map lists the templates of the forwarder whose records it was generated from: the
same Windows events sent through the OpenTelemetry Collector, Fluentd or Vector instead of Fluent
Bit have other templates, and arrive whole until a map is generated from them.

Where things run: the tool runs with Python 3.9 or later on the Receiver's host, from a copy of
the package unpacked there, because it writes the cap file the Receiver reads; the generated app
folders are kept there too. From that host it needs the search head's management port (8089) and
the HTTP Event Collector of every instance that parses the compact events. `tenx_dml`, the compact
index and `tenx_probe` are created where events are indexed (on an indexer cluster, in the cluster
bundle), and the HTTP Event Collector tokens on every instance that takes them. `--splunkd` names a
search head that searches those indexes and is not a member of a search head cluster. Each Receiver
has its own cap file and its own scheduled `check`.

1. Before compact events are sent, set the Receiver to compact only the templates a cap file lists.
   In its configuration folder (`$TENX_CONFIG`), set `fieldNames` to `[templateHash]` in
   `pipelines/run/receive/compact/config.yaml` (`default: false` is the shipped value). Create the
   cap file with its header row:

   ```sh
   mkdir -p /etc/tenx/win
   printf 'pattern_hash,value\n' > /etc/tenx/win/compact-cap.csv
   ```

   The first row is a header; the Receiver matches the template hash against the first column,
   whatever the header names it, and reads `true` or `false` from the second. Start the Receiver
   with these arguments:

   ```
   @run/input/forwarder/fluentbit @apps/receiver varMaxRecurIndexes 0 timestampZone UTC timestampMaxPerObject 1 groupJoinLines false compactReceiverLookupFile /etc/tenx/win/compact-cap.csv
   ```

   Leave `receiverOptimize true` out of them: with it the Receiver compacts every template, listed or
   not, so events would be compact before their fields can be written.

   With the published image, the edit to the shipped `compact/config.yaml` is one: the two lines
   `fieldNames:` and `- $=yield TenXEnv.get("symbolMessageField")` become `fieldNames: [templateHash]`.
   These lines copy the shipped file out of the image:

   ```sh
   docker create --name tenx-config log10x/edge-10x:1.1.181
   docker cp tenx-config:/etc/tenx/config/pipelines/run/receive/compact/config.yaml compact-config.yaml
   docker rm tenx-config
   ```

   Fluent Bit and the Receiver then run as in
   [Fluent Bit Beside the Receiver](#fluent-bit-beside-the-receiver), with the Receiver's arguments
   above:

   ```sh
   docker run -d --name tenx-fluentbit-in --network <network> \
     -v <fluent-bit-in.conf>:/fluent-bit/etc/fluent-bit.conf:ro \
     -v <parsers file>:/fluent-bit/etc/win-parsers.conf:ro -v <log folder>:/logs fluent/fluent-bit:5.1.5
   docker run -d --name tenx-receiver --network container:tenx-fluentbit-in \
     -v <edited compact config.yaml>:/etc/tenx/config/pipelines/run/receive/compact/config.yaml:ro \
     -v <host folder of the cap file>:/etc/tenx/win log10x/edge-10x:1.1.181 \
     @run/input/forwarder/fluentbit @apps/receiver varMaxRecurIndexes 0 timestampZone UTC \
     timestampMaxPerObject 1 groupJoinLines false compactReceiverLookupFile /etc/tenx/win/compact-cap.csv
   docker run -d --name tenx-fluentbit-back --network container:tenx-fluentbit-in --env-file <env file> \
     -v <fluent-bit-back.conf>:/fluent-bit/etc/fluent-bit.conf:ro -v <log folder>:/logs fluent/fluent-bit:5.1.5
   ```

   `<network>` is a Docker network from which the HTTP Event Collector is reachable. The env file
   sets each variable the configuration names, one `NAME=value` per line, such as
   `HEC_TOKEN=<HEC token>` for `Splunk_Token ${HEC_TOKEN}`. The tool is then given the cap file's
   path on the host, and the Receiver the path inside the container. The host folder need not be
   `/etc/tenx` (creating a folder there needs root).

   The first process's configuration holds:

   - `Parsers_File /fluent-bit/etc/win-parsers.conf` and `storage.path /logs/flb-storage` in
     `[SERVICE]`, and in that file the `win_xml` parser of
     [Fields of the Original Sourcetype](#fields-of-the-original-sourcetype-txf), step 1;
   - the source's `tail` input with `multiline.parser win_xml` and `storage.type filesystem`, as in
     that step;
   - the hand-off to the Receiver:

     ```
     [OUTPUT]
         Name        forward
         Match       <tag of the source>
         Host        127.0.0.1
         Port        24224
         Retry_Limit False
     ```

   The second process's configuration holds:

   - `storage.path /logs/flb-storage-back` and `HTTP_Port 2021` in `[SERVICE]`, and the input the
     Receiver's events come back on:

     ```
     [INPUT]
         Name         forward
         Listen       0.0.0.0
         Port         24225
         Tag_Prefix   tenx.
         storage.type filesystem
     ```

   - the template output of [Fluent Bit Beside the Receiver](#fluent-bit-beside-the-receiver), with
     `Match tenx.tenx-template`, which sends the template records to `tenx_dml`;
   - the `modify` filter and the `splunk` output of the source, as in
     [Fields of the Original Sourcetype](#fields-of-the-original-sourcetype-txf), step 1, with
     `event_sourcetype tenx_win` and `event_source XmlWinEventLog:Security` (step 5 below).

   Every event arrives whole, with all its fields, until its template is listed. From the first
   event on, send the mapped source with the map's compact sourcetype (`tenx_win` below), so whole
   and compact events of that source share it.

2. Let the **Consume KV** saved search store the template records (it runs every five minutes).

3. Export the stored templates from the search head's KV store, 2,000 rows a page, until a page
   holds no rows:

   ```sh
   curl -k -u admin "https://<search head>:8089/servicesNS/nobody/tenx-for-splunk/storage/collections/data/tenx_dml?output_mode=json&limit=2000&skip=0" > kv_0.json
   curl -k -u admin "https://<search head>:8089/servicesNS/nobody/tenx-for-splunk/storage/collections/data/tenx_dml?output_mode=json&limit=2000&skip=2000" > kv_1.json
   ```

   One read without `limit` returns at most 50 MB of rows, which can be fewer than the collection holds.
   `-u admin` asks for the password; in a script, pass `-H "Authorization: Bearer <token>"` instead.

4. Generate the field map app and its floor app:

   ```sh
   python3 tenx-for-splunk/bin/tenx_field_map.py gen \
     --records kv_0.json --records kv_1.json --target windows-security --rules lookup \
     --addon Splunk_TA_windows --leave-out SystemTime,EventRecordID --app-name fm_win \
     --cap-file /etc/tenx/win/compact-cap.csv --out fm_win
   ```

   `--leave-out SystemTime,EventRecordID` leaves out the two fields that take most of the map's
   index space; a plain search of a mapped event then lacks them, and the add-on's `event_time`,
   which it reads from `SystemTime`, is not on mapped events.

   `--cap-file` takes the cap file's path on this host, not the path inside the Receiver's container.

   `--addon` names a copy of the Windows add-on's folder on this host. The add-on downloads as a
   `.spl` archive; `tar -xzf` on it gives that folder, `Splunk_TA_windows/`. `gen` adds a copy of
   each of its rules that read the event's XML text (dest, src_ip, process_id and the 4688 process
   fields among them), reading the indexed field instead. Without it, those fields and `src` are
   missing on mapped events.

   `--target windows-security` reads templates of the rendered XML events above; on other records
   it writes an app with no rule and says so. This writes the apps `fm_win` and `fm_win_floor`
   and the file `compact-cap.csv.pending`, and
   prints the line step 5 adds to `tenx-events`. The compact sourcetype is `tenx_win`. The floor app
   holds a one-row lookup that Splunk reads when the field map's own file is missing, so events
   are kept and marked `tenx_unmapped=no_table` instead of dropped.

5. Copy `fm_win` and `fm_win_floor` to every instance that parses the compact events, and `fm_win`
   to the search head (see [What to Install on Each Tier](#what-to-install-on-each-tier)), add
   `tenx_compact_st::tenx_win` to the `tenx-events` macro as `gen` printed, for example
   `index=* (sourcetype::tenx_encoded OR tenx_compact_st::tenx_win)`, and send the compact Windows
   events with sourcetype `tenx_win`: the Fluent Bit lines of
   [Fields of the Original Sourcetype](#fields-of-the-original-sourcetype-txf), step 1, with
   `event_sourcetype tenx_win` and `event_source XmlWinEventLog:Security`: the add-on's Security
   rules apply only to events with that source. Restart a standalone instance or heavy forwarder
   after the first install. On an indexer cluster, put both apps in `manager-apps` on the cluster
   manager and push the bundle; a new field map app reaches the peers without a restart.

6. Create the probe index where the compact events are parsed: on a standalone instance or heavy
   forwarder `curl -k -u admin https://localhost:8089/services/data/indexes -d name=tenx_probe`, on
   an indexer cluster a `[tenx_probe]` stanza with `repFactor = auto` in an `indexes.conf` of the
   cluster bundle. The HTTP Event Collector token in `TENX_PROBE_HEC_TOKEN` must allow the probe
   index; a token that writes only there:
   `curl -k -u admin https://localhost:8089/servicesNS/nobody/splunk_httpinput/data/inputs/http -d name=tenx_probe -d token=<a new UUID> -d index=tenx_probe -d indexes=tenx_probe`. Then prove the field map and list its templates:

   ```sh
   TENX_SPLUNKD_TOKEN=<token> TENX_PROBE_HEC_TOKEN=<HEC token> python3 \
     tenx-for-splunk/bin/tenx_field_map.py activate \
     --app fm_win --cap-file /etc/tenx/win/compact-cap.csv \
     --splunkd https://<search head>:8089 --probe-hec https://<parsing instance>:8088 \
     --probe-index tenx_probe
   ```

   On an instance that still has Splunk's default self-signed certificate, the tool's certificate
   check fails; add `--tls-verify off`. For a certificate signed by an authority this host does not
   trust, add `--tls-ca-file <PEM file of that authority>`.
   `<token>` is a Splunk authentication token of a user
   whose role holds the capabilities `search` and `list_all_objects` and may search the probe
   index, the indexes that hold the map's compact events, and `_internal`; with `--probe-hec`,
   `edit_tcp` is not needed. `TENX_SPLUNKD_AUTH=<user>:<password>` works as well. `activate` sends one
   small probe event per new template through the HTTP Event Collector into the probe index, an
   index to keep out of data model and detection index lists. Probe events count against the
   Splunk licence like any indexed event: one compact line each, 194 to 787 bytes for the Windows
   templates and 136 to 2,576 bytes for the CloudTrail ones. When Splunk writes a probe's
   fields, that template moves from `compact-cap.csv.pending` into `compact-cap.csv`, and the
   Receiver, which rereads the file, then compacts its events. Nothing is restarted.

7. Schedule `check` every minute with the arguments of `activate`, for example from cron:

   ```sh
   TENX_SPLUNKD_TOKEN=<token> TENX_PROBE_HEC_TOKEN=<HEC token> python3 \
     tenx-for-splunk/bin/tenx_field_map.py check \
     --app fm_win --cap-file /etc/tenx/win/compact-cap.csv \
     --splunkd https://<search head>:8089 --probe-hec https://<parsing instance>:8088 \
     --probe-index tenx_probe --timeout 20 --poll 5
   ```

   Add `--tls-verify off` as in step 6. `check` sends the probe of a listed template. When it comes
   back without its fields, or is not indexed within `--timeout`, `check` empties `compact-cap.csv`,
   and the Receiver sends every event whole until `activate` has proven the templates again. Events
   indexed between the moment a listed template stops getting its fields and that `check` are kept,
   marked `tenx_unmapped`, and lack their index-time fields. After `check` empties the list, events
   the Receiver compacts before it rereads the file, within about 10 seconds, are kept and marked
   `tenx_unmapped`; every later event of that source arrives whole. `check` also counts the compact
   events of the map's sourcetype indexed without their fields since its previous run, and when
   there are any it fails and names the count and the reason. For `no_row` (a template the lookup
   file has no row for arrived compact) and `no_match` (an event held values its row does not take),
   the list is left as it is; for `bad_row` and `no_table` it is emptied as above. The saved search **Field Map Events Without Fields** counts such events for
   every map by index, sourcetype and reason; schedule it where a field map is installed.

A template that appears later arrives whole until steps 3, 4 and 6 run again. `gen` then changes
only the lookup file: copy `lookups/` of both apps over the installed ones (on a cluster, into
`manager-apps` and push the bundle) and run `activate`. Copy the lookup files with `cp` (not
`cp -p`), or touch them after copying. Splunk rereads a lookup file when its modification time
changes; a file put back with the time it had when Splunk last read it stays unread. A standalone
instance or heavy forwarder rereads the file within its `ingest_lookup_refresh_period_secs` (60
seconds by default) with no reload or restart, and a change to the lookup file alone reloads cluster
peers without a restart. If Splunk finds a field map's lookup file but cannot load it (the user Splunk runs as
cannot read it, it is not gzip, or it has no `hash` column), Splunk drops the map's compact events,
floor app or not, until `check` empties the list. Splunk's index-time `lookup()` drops the event on
such a file, and no rule can catch it. `check` counts the dropped events from Splunk's own log and
fails with that count. A row Splunk cannot use, an empty file, or a hash the file does not hold
keeps the event, marked `tenx_unmapped`. Keep the lookup files readable by the user Splunk runs as,
and change them only with the tool. With `check` run every minute, the list is empty within 80
seconds of the first dropped event, and the Receiver sends the map's events whole from 10 seconds
after that. Once a good file is back, Splunk reads it at once, except a file without a `hash` column
that Splunk read when it started: for that one, restart the instance that parses the events. After an upgrade of this app, `gen` can also write a new static rule;
`activate` then refuses the map until both apps are installed again whole, as in step 5.

Where several instances parse the compact events (indexer cluster peers, or several heavy
forwarders), give `activate` and `check` each node's HTTP Event Collector,
`--probe-hec https://<node>:8088` once per node. A template is then listed only when every node
writes its fields, and `check` empties the list when any node does not.

**AWS CloudTrail** has a second Receiver with its own cap file, `/etc/tenx/cloudtrail/compact-cap.csv`,
set up as in step 1, with `compactReceiverLookupFile /etc/tenx/cloudtrail/compact-cap.csv` in its
arguments. Steps 2, 3 and 5 are as for Windows Security, with the app `fm_cloudtrail`, the compact
sourcetype `tenx_cloudtrail` (`event_sourcetype tenx_cloudtrail` and
`Add tenx_sourcetype aws:cloudtrail` in the Fluent Bit lines) and
`tenx_compact_st::tenx_cloudtrail` in `tenx-events`. Step 4
generates the map with the AWS add-on's time settings, read from a copy of the add-on's
`default/props.conf`, so every compact event takes the raw event's `_time`:

```sh
python3 tenx-for-splunk/bin/tenx_field_map.py gen \
  --records kv_0.json --records kv_1.json --rules lookup --reader json \
  --sourcetype tenx_cloudtrail --rename aws:cloudtrail --reserved-names restore --mixed-names \
  --time-props Splunk_TA_aws/default/props.conf \
  --time-format '%Y-%m-%dT%H:%M:%S.%6N%Z' \
  --app-name fm_cloudtrail --cap-file /etc/tenx/cloudtrail/compact-cap.csv --out fm_cloudtrail
```

`--time-props` reads `[default]` and the stanza of the renamed sourcetype only, and refuses a stanza
that sets `TZ`, so it cannot follow an add-on that times events in a `source::` stanza, such as the
Sysmon add-ons.

Steps 6 and 7 take that map's app and cap file, and `--tls-verify off` as in step 6:

```sh
TENX_SPLUNKD_TOKEN=<token> TENX_PROBE_HEC_TOKEN=<HEC token> python3 \
  tenx-for-splunk/bin/tenx_field_map.py activate \
  --app fm_cloudtrail --cap-file /etc/tenx/cloudtrail/compact-cap.csv \
  --splunkd https://<search head>:8089 --probe-hec https://<parsing instance>:8088 \
  --probe-index tenx_probe

TENX_SPLUNKD_TOKEN=<token> TENX_PROBE_HEC_TOKEN=<HEC token> python3 \
  tenx-for-splunk/bin/tenx_field_map.py check \
  --app fm_cloudtrail --cap-file /etc/tenx/cloudtrail/compact-cap.csv \
  --splunkd https://<search head>:8089 --probe-hec https://<parsing instance>:8088 \
  --probe-index tenx_probe --timeout 20 --poll 5
```

FortiGate: one field map covers every log type. Events are stored under the add-on's own
sourcetype, and the Network_Traffic data model, tstats and the ESCU detections give the same results
as on raw events.

**Fortinet FortiGate** has its own Receiver and cap file, `/etc/tenx/fgt/compact-cap.csv`, set up as
in step 1. The add-on keeps the rules of each log type
under its own sourcetype (`fortigate_traffic`, `fortigate_utm`, `fortigate_event`,
`fortigate_anomaly`), so the sender sets `tenx_sourcetype` by the line's `type=`, with the Fluent Bit
lines of [Fields of the Original Sourcetype](#fields-of-the-original-sourcetype-txf) for FortiGate,
and sends the compact events with `event_sourcetype tenx_fgt`. The map stores each event under the
sourcetype its `tenx_sourcetype` names, while it is indexed, so `tstats ... by sourcetype` and the
add-on's event types see it as a raw event of that type. Steps 2, 3 and 5 are as for Windows
Security, with the app `fm_fgt` and `tenx_compact_st::tenx_fgt` in `tenx-events`. Step 4:

```sh
python3 tenx-for-splunk/bin/tenx_field_map.py gen \
  --records kv_0.json --records kv_1.json --target fortigate --rules lookup --leave-out time \
  --app-name fm_fgt --cap-file /etc/tenx/fgt/compact-cap.csv --out fm_fgt
```

`--leave-out time` leaves out the `time` field, which takes most of the map's index space; a plain
search of a mapped event then lacks it, and `_time` is set as before.

`--target fortigate` reads the add-on's key=value extraction and sets `_time` from the line's
`date=` and `time=`, as Splunk reads them on the raw event. Steps 6 and 7 take `--app fm_fgt
--cap-file /etc/tenx/fgt/compact-cap.csv`.

**Windows Security as classic text** (sourcetype `WinEventLog:Security`: a date line, then
`name=value` lines and the `Message=` block, not rendered XML) has its own map, Receiver and cap file,
`/etc/tenx/wincl/compact-cap.csv`. Fluent Bit starts a record at the event's date line and ends it
at the next one, or after 30 seconds without a new line; the `tail` input takes
`storage.type filesystem`, as in [Fluent Bit Beside the Receiver](#fluent-bit-beside-the-receiver):

```
[MULTILINE_PARSER]
    name          win_classic
    type          regex
    flush_timeout 30000
    rule          "start_state"  "/^\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2} [AP]M$/"       "cont"
    rule          "cont"         "/^(?!\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2} [AP]M$)/"  "cont"
```

and the `splunk` output sends the compact events with `event_sourcetype tenx_wincl`,
`event_source WinEventLog:Security` and `Add tenx_sourcetype WinEventLog`; the map stores each event
as `WinEventLog`, as the add-on stores the raw event. Step 4:

```sh
python3 tenx-for-splunk/bin/tenx_field_map.py gen \
  --records kv_0.json --records kv_1.json --target windows-security-classic --rules lookup \
  --addon Splunk_TA_windows --mixed-names --leave-out Message --app-name fm_wincl \
  --cap-file /etc/tenx/wincl/compact-cap.csv --out fm_wincl
```

`--target windows-security-classic` reads the header's `name=value` lines and the message's
`name:` lines as Splunk's own rules for `WinEventLog` sources do, and `--addon` adds the add-on's
rules that read a section of the text (`Subject_Account_Name`, `Target_Account_Name`,
`process_id` and others) for every template where their result does not depend on a value.
`--mixed-names` writes the field names the Receiver split into text and a value
(`Token_Elevation_Type`). `--leave-out Message` leaves out the message text, which takes most of the map's index space; a
plain search of a mapped event then lacks `Message` and `body`. Steps 6 and 7 take `--app fm_wincl --cap-file
/etc/tenx/wincl/compact-cap.csv`.

**Palo Alto Networks** (the Splunk Add-on for Palo Alto Networks; PAN-OS syslog in as `pan:log`) has
one map for the add-on's log types, with its own Receiver and cap file, `/etc/tenx/pan/compact-cap.csv`,
set up as in step 1. The add-on stores each line under `pan:traffic`, `pan:threat`, `pan:system` or
one of six more by the line's fourth value, so the sender does the same and sets `tenx_sourcetype`;
a line the add-on's rules do not route keeps `pan:log`:

```
[FILTER]
    Name                   rewrite_tag
    Match                  pan
    Rule                   $log ^[^,]+,[^,]+,[^,]+,(TRAFFIC|THREAT|SYSTEM|CONFIG|HIPMATCH|CORRELATION|USERID|GLOBALPROTECT|DECRYPTION), pan.$1 false
    Emitter_Name           pan_type
    Emitter_Storage.type   filesystem
    Emitter_Mem_Buf_Limit  0
[FILTER]
    Name    modify
    Match   tenx.pan.TRAFFIC
    Add     tenx_sourcetype pan:traffic
```

with one `modify` per type (`tenx.pan.THREAT` adds `pan:threat`, and so on) and one for `tenx.pan`
that adds `pan:log`, and sends the compact events with `event_sourcetype tenx_pan`. The emitter
buffers on disk with no memory limit (`storage.path` set under `[SERVICE]`): with memory only, while
the HTTP Event Collector was slow to accept, it passed 122,726 of 1,902,151 lines on untouched, stored
as `pan:log`. Step 4:

```sh
python3 tenx-for-splunk/bin/tenx_field_map.py gen \
  --records kv_0.json --records kv_1.json --target palo-alto --rules lookup \
  --addon Splunk_TA_paloalto_networks --app-name fm_pan \
  --cap-file /etc/tenx/pan/compact-cap.csv --out fm_pan
```

`--target palo-alto` reads each line as the add-on's `DELIMS = ","` and `FIELDS` rules do, the names
for each log type taken from `--addon`, and sets `_time` as Splunk reads a `pan:log` line. Those rules
also read a compact event's text, the Receiver's comma-separated line, so the map writes `tenx_blank`,
the columns that line reaches where the raw event has no value, and nulls what the rules read there at
search time, in the add-on's own calculated fields as well. Searches over compact Palo Alto events take
longer for it: about twice as long for a `stats` over six fields of 100,000 events, about five times
when every field of every event is read. Steps 6 and 7 take `--app fm_pan --cap-file
/etc/tenx/pan/compact-cap.csv`. Another source whose add-on reads positional values (`DELIMS` with
`FIELDS`) takes `--reader csv`, with `--addon` or `--columns` for the names.

`tstats` reads the indexed sourcetype, which stays the compact one with or without a field map, so
`tstats` by or on the original sourcetype counts no compact event; `tenx_sourcetype` holds the
original. Use `where (sourcetype=XmlWinEventLog OR tenx_sourcetype=XmlWinEventLog)`, or a data
model, which applies the rename. A FortiGate or classic Windows map stores each event under its original
sourcetype while it is indexed, so there `tstats` by sourcetype counts it as a raw event.

For all fields on a plain search of mapped CloudTrail events, set `indexed_kv_limit = 0` under
`[kv]` in `limits.conf` on the indexers and heavy forwarders, in the cluster bundle on a cluster (a
search head does not pass `limits.conf` to its peers). It takes a restart; on a cluster the bundle
push restarts the peers one by one. Splunk's default, 200, caps the indexed fields a plain search
shows on one event; 0 shows every field. Data model counts and detections through the map are the
same at either value.

Checked with the Windows add-on 12.0.0, the AWS add-on 8.3.1, the Fortinet FortiGate Add-on 1.6.10
and CIM 8.8.0 against the same events indexed raw; the results are in the
[listing's checks](https://github.com/log-10x/splunk-app/blob/main/splunkbase/LISTING.md#checks-run-on-this-package).
These limits remain. Event types that match words of the original text, such as `err0r` in the
Windows add-on and `aws_cloudtrail_delete_events` in the AWS add-on, match a mapped event only where
its compact text holds the word. On
Windows EventID 4798, 5156 and 5157, `dest` is the event's Computer and `src_ip` and `dest_ip` are
not written. The add-on's XML block fields `EventData_Xml` and `System_Props_Xml` are not written.
`vendor_privilege` and `privilege_id` carry `-` on events where the raw event has neither. A value
that holds line breaks and tabs is written with spaces in their place. A JSON string whose escape
the Receiver split from the value after it, such as a CloudTrail `sessionToken`, is written for `\/`
and for `\u003c`, `\u003e`, `\u0026`, `\u003d` and `\u0027` as the character each stands for, and for
`\n`, `\t` and `\r` with a space; with any other escape there, that field is not written. A plain search
shows a mapped field longer than 1,000 characters, such as a PowerShell `ScriptBlockText`, cut to its first 1,000;
`tstats` on the field reads it whole. A template with more than 984 values
gets no row, and its events arrive whole. An event whose compact value holds a line feed or another
control character, such as a NUL byte in a FortiGate line, gets no fields and is marked
`tenx_unmapped=no_match`. With `--reserved-names restore`, a mapped CloudTrail
event carries `extracted_eventType` beside `eventType`, and a mapped FortiGate UTM event
`extracted_eventtype` beside `eventtype`, and a mapped Palo Alto decryption event `extracted_timestamp`
beside `timestamp`. The Receiver keeps the log type `TRAFFIC`, `SYSTEM`, `CONFIG`,
`USERID`, `DECRYPTION` or `CORRELATION` as template text, but makes `THREAT`, `GLOBALPROTECT` and
`HIPMATCH` a value, so the map cannot tell which add-on rules read such a line: threat, GlobalProtect
and HIP match events arrive whole, with the add-on's own fields as on raw events. Mapped events carry no `date_*` fields
(`date_hour`, `date_wday` and the others), which Splunk gives raw events it reads from a file, so a
detection that reads them, such as a business-hours one, matches no mapped event. On classic
Windows events, values such as `Access_Reasons` have spaces in place of line breaks and tabs, as do
`Message` and `body` when the map writes them, and the add-on's fields read from lines of the message
(`privilege_id`, `vendor_privilege`, `privilege`) and `event_time` are not written, and `src_nt_domain` takes every
value of `Security_ID` where the raw event takes the subject's.

## Which Searches Change When a Source Moves

`tenx_search_report.py`, in the app's `bin` folder, reads the saved searches, alerts and dashboards
of a search head and says, for each one, what moving the named sourcetypes or indexes to compact
events asks of it. It reads them over the management port, or from a copy of the search head's
`etc/apps` and `etc/users` folders. It changes nothing and starts no search: it reads saved searches
and views, and expands each search's macros with Splunk's search parser. It runs with Python 3.9 or
later, and reports the objects that the user it runs as can read.

```sh
TENX_SPLUNKD_TOKEN=<token> python3 tenx-for-splunk/bin/tenx_search_report.py \
  --splunkd https://<search head>:8089 --sourcetype XmlWinEventLog --index wineventlog \
  --field-map XmlWinEventLog --csv report.csv
```

`--sourcetype` and `--index` name what moves, each as often as needed. `--field-map` names a moved
sourcetype that a field map covers; without it the report says what the move asks without a field
map. Add `--tls-verify off` for a management port with Splunk's default self-signed certificate,
and `--app <app>` to report one app. From files, `--dir` takes the place of `--splunkd`:

```sh
python3 tenx-for-splunk/bin/tenx_search_report.py --dir <copy of etc> \
  --sourcetype XmlWinEventLog --index wineventlog --csv report.csv
```

It prints one line per saved search, alert, dashboard panel, base search and dashboard input, with
its app, owner, kind, verdict and reason, then the number of each verdict. The CSV file adds each
search and, where a macro is needed, the search with the macro in place: index, host, source and
time terms before it, every other term after it.

| Verdict | Meaning |
|---|---|
| unchanged | Runs as written and returns what it returns on the raw events |
| needs tx | `tx` in front of its search terms; it reads only the events' text |
| needs txf | `txf` in front of its search terms |
| needs field map | Reads data models, which a field map serves as written |
| limit | A shape this README lists as behaving differently on compact events; the reason quotes it |
| not classified | A macro the tool cannot expand, `map`, `savedsearch`, a subsearch that writes search terms, a dashboard token without a default, or a shape not measured |
| not affected | Reads none of the moved data |

Without a field map, searches of the moved data need `tx` or `txf`, except searches that count by
index, host and source; data models, and `tstats` on fields other than index, host and source, need a
field map. With a field map, searches on fields run as written, also where a value is template text. Three kinds still need `txf`: a search
on words of the text, a search whose later commands read `_raw` (`rex`, `regex`, `spath`, `search`
on words), and a report that lists events. An alert that lists events fires as before, with the
same number of events, and its results show the compact text.

Checked on Splunk Enterprise 10.4.3 with the Windows add-on 12.0.0, the AWS add-on 8.3.1, the
FortiGate add-on 1.6.10 and CIM 8.8.0, on 117 saved searches, 18 of them ESCU detections, and two
dashboards over Windows Security, CloudTrail and FortiGate events, each run on the same events raw
and compact, without and with a field map (FortiGate without); the results are in the
[listing's checks](https://github.com/log-10x/splunk-app/blob/main/splunkbase/LISTING.md#checks-run-on-this-package).

## What to Install on Each Tier

In a distributed deployment, run `$SPLUNK_HOME/bin/slim partition tenx-for-splunk-<version>.tar.gz`
once, on a clean copy of the package. Its `_indexers` package holds the parsing settings and
schedules no search; it goes on the indexers and on heavy forwarders. The search heads take the
`_search_heads` package or the whole app. The `_forwarders` package it also writes is not used: on
a heavy forwarder it logs error lines at restart. `slim` prints "Undefined setting" warnings for
settings it does not know, among them `python.required` and `INGEST_EVAL`, and each archive it
writes holds a folder with the package archive inside.

| Tier | What to install |
|---|---|
| Search heads (through the deployer for a search head cluster) | the `_search_heads` package or the whole app, the add-ons of the original sourcetypes, CIM, and the field map apps |
| Indexers (through the cluster manager's bundle) | the `_indexers` package, the add-ons, the field map apps with their floor apps, and `indexed_kv_limit` where needed |
| Heavy forwarders that parse the compact events | the `_indexers` package, the add-ons, and the field map apps with their floor apps |
| Universal Forwarders | nothing of 10x |

The whole app also works on indexers and heavy forwarders, and its scheduled searches then run
there with nothing to do. Replacing the whole app with the `_indexers` package on the indexers, or
the reverse, takes one rolling restart; updating the whole app in place takes none. The template
collection reaches the indexers in the knowledge bundle, so `tx` and `txf` need nothing more on
them.

### Receiver Beside a Heavy Forwarder

Where Universal Forwarders send to a heavy forwarder, the Receiver can run on the heavy forwarder's
host, and the Universal Forwarders stay as they are. The heavy forwarder parses the events with its
add-ons and writes the chosen sourcetypes to its ingest actions file destination, one JSON line per
event with its time, host, source, sourcetype and index. Fluent Bit reads those files, hands each
event to the Receiver and sends what comes back to the indexers' HTTP Event Collector, so the heavy
forwarder's index-time rules apply before compaction. The steps are in the Log10x documentation:
[Receiver beside a heavy forwarder](https://doc.log10x.com/run/input/forwarder/splunkUF/#receiver-beside-a-heavy-forwarder).
In that arrangement, a customer's `WRITE_META` fields must be named on the Fluent Bit output; route
by sourcetype when an index override runs first.

## Getting Started

### Step 1: Configure the Receiver

Set up the Receiver and its forwarder as the [Splunk setup page](https://doc.log10x.com/apps/receiver/compact/splunk/)
of the Log10x documentation describes, so that they send:

1. **Templates** to a Splunk HTTP Event Collector (HEC) or file input with:
   - Sourcetype: `tenx_dml_raw_json`
   - Format: `{"templateHash":"<hash>", "template":"<pattern>"}`

2. **Encoded events** with:
   - Sourcetype: `tenx_encoded`
   - Format: `~<hash>,<var0>,<var1>,...`

3. **Receiver settings** this app relies on: the arguments `receiverOptimize true`,
   `varMaxRecurIndexes 0`, `timestampZone UTC`, `timestampMaxPerObject 1` and `groupJoinLines false`. The [repository README](https://github.com/log-10x/splunk-app/blob/main/README.md#receiver-side-configuration)
   explains each one.

### Step 2: Verify Template Ingestion

After sending some test data, verify templates are being received:

```spl
index=* sourcetype=tenx_dml_raw_json earliest=-15m
| head 10
```

### Step 3: Check KV Store Population

Wait five minutes for the "Consume KV" saved search to run, or run the
[backfill search](#loading-templates-indexed-earlier), then verify:

```spl
| inputlookup tenx-dml-lookup
| stats count
```

### Step 4: Test Expansion

Search for compact events and expand. An event `{"message":"10x engine connected to ..."}` is the
Receiver's status record, indexed once per start when the forwarder's output matches `tenx.*`;
match each source's own tag to keep it out:

```spl
index=* sourcetype=tenx_encoded earliest=-15m
| head 100
| `tenx-inflate`
```

### Step 5: Validate Results

Compare inflated events to your original logs to ensure accuracy:

```spl
index=* sourcetype=tenx_encoded earliest=-15m
| head 10
| `tenx-inflate-debug`
| table _raw, tenx_hash, tenx_ts_sec, tenx_ts_f
```

---

## Technical Reference

### Encoded Event Format

```
~<hash>,<var0>,<var1>,<var2>,...
```

- `~`: Optional prefix (handled by extraction regex)
- `<hash>`: Template hash identifier
- `<var0>`: First variable (typically epoch timestamp in milliseconds or nanoseconds)
- `<var1>...`: Additional variable values

### Template Format

Templates use `$` as the variable separator:

```
$ INFO [main] MyService - User $ performed action $ at $
```

Special timestamp format:
```
$(<format>): Timestamp placeholder with Java SimpleDateFormat pattern
$(epoch): Special case for milliseconds since epoch
```

Examples:
- `$(yyyy-MM-dd'T'HH:mm:ss.SSS'Z')`: ISO 8601 format
- `$(epoch)`: Unix epoch milliseconds

### Expansion Macro Logic

The `tenx-inflate` macro performs these operations:

1. **Parse variables**: `makemv delim="," tenx_vars`
   - Converts comma-separated variable string to multivalue field

2. **Lookup template**: `lookup tenx-dml-lookup _key AS tenx_hash`
   - Retrieves template parts from KV store

3. **Split the timestamp**: the first ten digits of `tenx_var_0` are epoch seconds; the rest
   is the fraction, cut to the precision the template's format asks for.

4. **Reconstruct event**: Combines template parts with variables using `mvzip` and `mvappend`

5. **Format timestamp**: Replaces the `__TENX_TS__` placeholder with the time rendered in UTC by `strftime`

6. **Cleanup**: Removes intermediate `tenx_*` fields

### Field Extraction Regex

The `tenx-hash-vars-extraction` transform:

```regex
^~?(?<tenx_hash>[^,]+)(?:,(?<tenx_var_0>[^,]+)(?:,(?<tenx_vars>.*))?)?
```

- `~?`: Optional tilde prefix
- `(?<tenx_hash>[^,]+)`: Capture hash (everything up to first comma)
- `(?:,(?<tenx_var_0>[^,]+)...)?`: Optionally capture the first variable (timestamp), so `~<hash>` alone also matches
- `(?:,(?<tenx_vars>.*))?`: Optionally capture remaining variables

### Timestamp Format Conversion

The `tenx_dml_builder.py` script converts Java SimpleDateFormat to Splunk strftime:

| Java | Splunk | Description |
|------|--------|-------------|
| `yyyy` | `%Y` | 4-digit year |
| `yy` | `%y` | 2-digit year |
| `MMMM` | `%B` | Full month name |
| `MMM` | `%b` | Abbreviated month |
| `MM` | `%m` | 2-digit month |
| `dd` | `%d` | Day of month |
| `HH` | `%H` | Hour (24-hour) |
| `mm` | `%M` | Minute |
| `ss` | `%S` | Second |
| `SSS` | `%3Q` | Milliseconds |
| `Z` | `%z` | Timezone offset |

### API Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `/servicesNS/{owner}/{app}/storage/collections/data/{collection}/` | KV store operations |
| `/servicesNS/{owner}/{app}/storage/collections/data/{collection}/batch_save` | Mark templates whose searchable copy is written |
| `/servicesNS/nobody/{app}/search/jobs` | Run the `collect` search that writes the searchable copy |

---

## Troubleshooting

### Dashboard Shows "No Results Found"

#### Time Range in Your Own Dashboards

For an all-time panel, set `<earliest>1</earliest>` and leave `<latest>` empty. Splunk Web
reads `<earliest>0</earliest>` as no time constraint, not as epoch 0.

#### Dashboards Show Zero Events

**Problem**: the 10x dashboards report no events although compact events are indexed.

**Solution**: the dashboards find events through the `tenx-events` macro. Set it to the index
and sourcetype your compact events use; see [Pointing the Dashboards at Your Compact
Events](#pointing-the-dashboards-at-your-compact-events).

#### Subsearch Limitations

**Problem**: `appendpipe [| tstats ...]` and similar subsearch patterns fail silently in dashboard context.

**Solution**: pivot with `untable` instead of appending a subsearch:
```spl
| stats sum(enc) as enc, sum(inf) as inf
| eval Encoded=round(enc/1048576, 2), Original=round(inf/1048576, 2)
| fields Encoded, Original
| untable _row metric MB
```

#### tstats vs search Command

**Problem**: `tstats` works but `search` returns nothing.

**Explanation**:
- `tstats` searches tsidx (index metadata) - faster, always available
- `search` searches raw events - requires correct index/time range permissions

**Diagnostic approach**, one search at a time:
```spl
| tstats count where `tenx-events`
```
```spl
| eventcount summarize=false index=*
```
```spl
`tenx-events` | stats min(_time) as earliest, max(_time) as latest
| eval earliest=strftime(earliest, "%Y-%m-%d"), latest=strftime(latest, "%Y-%m-%d")
```


### Templates Not Appearing in KV Store

Templates indexed before the app was installed are loaded only by the
[backfill search](#loading-templates-indexed-earlier); run it once.

1. **Check saved search execution:**
   ```spl
   index=_internal sourcetype=scheduler savedsearch_name="Consume KV"
   | table _time, status, run_time
   ```

2. **Check alert action logs:**
   ```bash
   tail -f $SPLUNK_HOME/var/log/splunk/tenx_dml_to_kv.log
   ```

3. **Verify template format:**
   ```spl
   index=* sourcetype=tenx_dml_raw_json
   | head 5
   | table templateHash, template
   ```

### A `tx` Search Returns No Results

- **The time range comes after `tx`.** Move `earliest=` and `latest=` before it; in the
  search bar the job stops with a message that says so.
- **The search goes through the REST export endpoint.** With `output_mode=csv`, and on Splunk
  10.4 and 10.6 with `json`, `/services/search/jobs/export` returns an empty body when the search
  stops; read the message with `output_mode=xml` or through `/services/search/jobs`.
- **The words belong to a template stored in the last few minutes.** Wait for the next
  Consume KV run, or store it at once with the search under
  [Loading Templates Indexed Earlier](#loading-templates-indexed-earlier).

### Expansion Returns Empty or Wrong Results

1. **Check KV store has entry for hash:**
   ```spl
   | inputlookup tenx-dml-lookup where _key="<your_hash>"
   ```

2. **Debug with the `tenx-inflate-debug` macro:**
   ```spl
   index=* sourcetype=tenx_encoded tenx_hash="<your_hash>"
   | head 1
   | `tenx-inflate-debug`
   | table *
   ```

3. **Verify field extraction:**
   ```spl
   index=* sourcetype=tenx_encoded
   | head 5
   | table _raw, tenx_hash, tenx_var_0, tenx_vars
   ```

### Timestamp Shows Wrong Value

1. **Check timestamp precision detection:**
   ```spl
   index=* sourcetype=tenx_encoded
   | head 5
   | `tenx-inflate-debug`
   | table tenx_var_0, tenx_ts_sec, tenx_ts_f
   ```

2. **Verify template timestamp format:**
   ```spl
   | inputlookup tenx-dml-lookup
   | search timestamp_format!=""
   | table _key, timestamp_format
   ```

### Performance Issues

1. **Add index constraints:**
   ```spl
   index=myindex sourcetype=tenx_encoded earliest=-1h
   | `tenx-inflate`
   ```

2. **Filter before expansion:**
   ```spl
   index=myindex sourcetype=tenx_encoded tenx_hash="known_hash*"
   | `tenx-inflate`
   ```

3. **Check KV store size:**
   ```spl
   | inputlookup tenx-dml-lookup
   | stats count
   ```

---

## License

This app is released under the MIT License, see [LICENSE](LICENSE). The bundled libraries
keep their own licenses, see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

Compacting events requires the Log10x Receiver, which is commercial. The app in this
directory is MIT-licensed open source.

---

## Support

- Issues and feature requests: [GitHub Issues](https://github.com/log-10x/splunk-app/issues)
- Direct support: [support@log10x.com](mailto:support@log10x.com)
