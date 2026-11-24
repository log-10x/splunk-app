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
| `tenx-raw-events` | Raw events of the same sources, such as those indexed before the Receiver, that `tx` and `txf` return as they are; names none by default (see [Raw Events from Before the Receiver](#raw-events-from-before-the-receiver)) |
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
| Consume KV | every 5 minutes | Stores in the KV store every template record indexed since the last one it stored |
| Backfill KV | not scheduled | The same load from the start of the index, after the KV store was emptied or restored |
| Recompile Compiled Alerts | every 15 minutes | Runs `tenxrecompile` so compiled alerts pick up new templates |
| Rebuild Field Replay | every hour | Runs `tenxreplay`, which writes the replay macros `txf` runs |
| Rebuild Field Replay When New | every 5 minutes | Runs `tenxreplay` for original sourcetypes not yet covered |

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
├── bin/                         # Python scripts, see Python Scripts above
├── default/
│   ├── alert_actions.conf       # Alert action definition
│   ├── app.conf                 # App metadata
│   ├── collections.conf         # KV store schema
│   ├── commands.conf            # The tenxprefilter, tx, tenxsearch, tenxrecompile and tenxreplay commands
│   ├── macros.conf              # SPL macros, including tx
│   ├── props.conf               # Sourcetype definitions
│   ├── restmap.conf, web.conf   # The /tenx-search and /tenx-alert endpoints
│   ├── savedsearches.conf       # Consume KV, Backfill KV, Recompile Compiled Alerts, Rebuild Field Replay,
│   │                            # Rebuild Field Replay When New
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
search = | makeresults
dispatch.earliest_time = -1m
dispatch.latest_time = now
```

Each run stores every template record indexed since the last one it stored, so a longer interval delays
new templates and skips none.

### Loading Templates Indexed Earlier

Every five minutes the **Consume KV** saved search stores every template record indexed since the last
one it stored, and a run that stops is continued by the next. Its first run after an install or an
upgrade reads every template record in the index. To load them again after the KV collection was emptied
or restored, run this as an admin or power user:

```spl
| makeresults | sendalert tenx_dml_to_kv param.from=0
```

The **Backfill KV** saved search holds the same search; the **Run** button does not fire its alert
action, so run the search above. A run that stops before it ends leaves stored and copied what it
finished, and the next run continues; Diagnostics shows the last run that did not finish.

Diagnostics counts the template hashes indexed against those the KV store holds; `tx` and `txf` warn
when Consume KV failed, is still loading, or has not run for fifteen minutes.

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
`index=* (sourcetype::tenx_encoded OR tenx_sourcetype::*)`, finds the app's sourcetype, and every
event that carries `tenx_sourcetype`, in every index that can be searched. Set it to the compact
index, and add any custom sourcetype, under **Settings > Advanced search > Search macros**. Write each sourcetype in the indexed form `sourcetype::`:
beside the prefilter `tx` adds to this clause, Splunk dropped some events matched with
`sourcetype=`:

```spl
index=my_compact_index (sourcetype::tenx_encoded OR sourcetype::my_custom_sourcetype OR tenx_sourcetype::*)
```

Naming the index makes every panel faster. Raw events of the same sources, such as those
indexed before the Receiver, are named in a second macro; see the next section.

### Compact Events Under the Original Sourcetype

An add-on keys its event types, tags and field rules on its sourcetype, so its data models do not read
compact events indexed as `tenx_encoded`. Where the Receiver attaches the fields those models read
(its `compactFields` option), the instances that parse the compact events can index each one under its
original sourcetype instead. Add this line to a `local/props.conf` of the app on the indexers or the
heavy forwarder that parse them:

```
[tenx_encoded]
TRANSFORMS-tenx_type = tenx-original-sourcetype
```

An event that carries `tenx_sourcetype` is then indexed under its first value, once the rules of
`tenx_encoded` have parsed it. Set `tenx_sourcetype` to the sourcetype the raw events are searched
under, after any rename the add-on makes while it parses them. To limit the rule to some sources, put
the line in a `[source::<source>]` or `[host::<host>]` stanza in place of `[tenx_encoded]`.

Turn it on only for sources whose Receiver attaches the fields that the add-on's event types and models
read; without them, an event can count in a model with those fields empty. A Universal Forwarder's
compact files carry attached fields only as relay lines (see "Universal Forwarder Relay Lines"), so
leave out sources whose files hold the compact text alone.

`tx`, `txf` and the dashboards find these events by `tenx_sourcetype` and expand them as before. A field
the Receiver attached and the expanded text also holds keeps the extracted values alone, once the
"Rebuild Field Replay" saved searches have run. On the file routes, behind a heavy forwarder or a
Universal Forwarder, the Receiver attaches the fields with `compactFieldsForm text`, `compactFieldsKey
meta` and `compactFieldsSeparator ::`, and `[tenx-record-unwrap]` adds them to the event's indexed fields.

On the route of [Fluent Bit Beside the Receiver](#fluent-bit-beside-the-receiver), give the Receiver the
source's profile, such as `@run/fields/windows-security-xml.yaml`, and leave the three options above
unset. Each compact record then comes back with its fields as one JSON object under `fields`.

Fluent Bit's Splunk output with `event_key` sends that value as the event and leaves `fields` out. In
the second process, replace the compact events' `modify` filter and output with these:

```
[FILTER]
    Name              modify
    Match             tenx.src.app
    Add               tenx_sourcetype <original sourcetype>

[FILTER]
    Name              nest
    Match             tenx.src.app
    Operation         lift
    Nested_under      fields
    Add_prefix        fields.

[FILTER]
    Name              modify
    Match             tenx.src.app
    Rename            tenx_sourcetype fields.tenx_sourcetype
    Rename            log event
    Add               sourcetype tenx_encoded
    Add               index <compact index>
    Add               source <original source>

[FILTER]
    Name              nest
    Match             tenx.src.app
    Operation         nest
    Wildcard          fields.*
    Nest_under        fields
    Remove_prefix     fields.

[FILTER]
    Name              record_modifier
    Match             tenx.src.app
    Allowlist_key     event
    Allowlist_key     fields
    Allowlist_key     sourcetype
    Allowlist_key     index
    Allowlist_key     source

[OUTPUT]
    Name              splunk
    Match             tenx.src.app
    Host              <HEC host>
    Port              8088
    Splunk_Token      ${HEC_TOKEN}
    TLS               On
    splunk_send_raw   On
    Retry_Limit       False
```

The filters move `tenx_sourcetype` in with the attached fields and make each record an HTTP Event
Collector event, which `splunk_send_raw On` sends as it stands. The HEC indexes every key of `fields`,
and a list as several values. Set `source` to the source of the raw events, which the Windows add-on
reads.

The last filter drops every other key of the record. The HEC refuses a request whose record holds a key
it does not read, such as those a `kubernetes` filter adds. Fluent Bit does not send that request again.

Some add-ons set the sourcetype from the event text, as the FortiGate add-on does from `type`. For such
a source, put one `modify` filter per value in place of the first one:

```
[FILTER]
    Name              modify
    Match             tenx.src.app
    Condition         Key_value_equals $fields['type'] traffic
    Add               tenx_sourcetype fortigate_traffic
```

### Raw Events from Before the Receiver

A source that sent raw events before the Receiver was installed keeps them in its index, next to
its compact events. `tx` and `txf` read the compact events (`tenx-events`) and the raw events the
`tenx-raw-events` macro names. That macro names none by default, so a search over both periods
returns only the compact events. To have one search return both, name the raw events there by
index and sourcetype, in the indexed form:

```spl
index=web (sourcetype::access_combined OR sourcetype::fortigate_traffic)
```

Raw events come back as they were indexed, with the fields Splunk gives them; compact events are
expanded. Search fields across both periods with `txf`: through `tx`, a compact event has only the
fields in its text, while a raw event also has its add-on's fields. Only `tx` and `txf` read this
macro; the dashboards and the field replay read `tenx-events` alone.

When the indexes a `tx` or `txf` search reads hold raw events of the original sourcetype of its
compact events, in its time range, and `tenx-raw-events` does not name them, the search shows a
warning. The check needs compact events that carry `tenx_sourcetype` (see
[Fields of the Original Sourcetype](#fields-of-the-original-sourcetype-txf)); without it, set the
macro when a source moves to the Receiver.

### Events Sent as Text

The Receiver sends some events as their own text, in the same stream and sourcetype as the compact
events: an event of 65,535 characters or more and, with its `templateCreateAfter` option, an event
whose template it has not made yet. A compact event starts with `~`; an event sent as text never
does, so the app tells the two apart by that first character.

The Receiver's Forward output, which Fluent Bit, Fluentd and Vector read back, starts every compact
event with `~`. A compact event that reaches Splunk without it is returned as it is, as text.

`tx`, `txf`, the `| tx` command, the dashboard hook and compiled alerts find such an event by the
words of its text and return it as it is, without `tenx_expand_refused`. Its `_time`, and through
`txf` its fields, are those of a compact event of the same line. The dashboard counts it in its
event totals and shows these events as one row, `(sent as text)`, in its template tables.

A log line that itself starts with `~` is never sent as text: the Receiver makes its template on
first sight, and `tx` expands it back to the line. A raw event named in `tenx-raw-events` whose
text starts with `~` is read as a compact event: when no template has the text before its first
comma as its hash, it comes back as it is, with `tenx_expand_refused` set to `no-template`.

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
  with a warning: the same result, more slowly. A search that holds more than one `tx` or `txf`
  does the same for each of them. Inside another subsearch, and in a search that holds more than
  one `tx` or `txf`, a wildcard inside a word (`Se*Privilege`) and `TERM()` of part of a longer term
  match as after a pipe, so they can return more events than the same search on the original lines.
- A compact event is one record the forwarder sent: a stack trace the forwarder joined into one
  record is one event, a count counts events, and words joined with AND can match on different lines
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
the result, never narrower. A `tx` word search reads the template store, which adds a few seconds per
search where it holds hundreds of thousands of templates. The answer for each word is kept in the
`tenx_dict_cache` collection, and a later search for the same word reads only the templates stored in
the hours since. Every template is read again once a day, after the app is installed or upgraded, and
after the template load is run from the start of the index.

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
  minutes. Until then its events stay compact, with `tenx_expand_refused` set to `no-template`, and a
  search for a word of that template does not select them.
- While the KV store is loaded again after it was emptied or restored, `tx` expands events but a
  search for a word of a template not yet stored does not select them; Diagnostics shows the load.

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

`groupJoinLines false` keeps each forwarder record one Splunk event; without it, the Receiver joins a
record that reads as a continuation line, such as a line of a stack trace, to the event before it.
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

[FILTER]
    Name              modify
    Match             tenx.src.app
    Add               tenx_sourcetype <original sourcetype>

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
    event_field       tenx_sourcetype $tenx_sourcetype
    Retry_Limit       False
```

The `modify` filter gives each record the sourcetype its raw events have, and
`event_field tenx_sourcetype $tenx_sourcetype` sends it as an indexed field, which `txf` reads and
[Compact Events Under the Original Sourcetype](#compact-events-under-the-original-sourcetype) uses.

A multi-line source takes a multiline parser with `flush_timeout 30000` on its `tail` input, as the
Windows sources below do. Every `rewrite_tag` filter takes `Emitter_Storage.type filesystem` and
`Emitter_Mem_Buf_Limit 0`. Leave these unset: `storage.pause_on_chunks_overlimit`, `rate_gate`, and
memory storage with `Mem_Buf_Limit`, on a `tail` input; `Mem_Buf_Limit` and any pause option on the
second process's `forward` input; `storage.total_limit_size` on any output.
Each setting avoids a way Fluent Bit 5.1.5 loses or holds back records: a paused `tail` input drops
a multi-line event it completes while paused, a size limit on an output drops its oldest chunks, a
`rewrite_tag` filter whose emitter is full passes records on under their original tag, and in one
process the events coming back from the Receiver wait behind the backlog of the logs being read.
Fluent Bit's Splunk output has no indexer acknowledgement, so when the HEC answers 503, a chunk
Fluent Bit sends again can be indexed twice, as on any Fluent Bit path to HEC, raw events included.

While Fluent Bit takes the Receiver's events slower than they come, the Receiver logs the WARN line
`forward output buffer full (the destination takes events slower than they come): events wait until
it takes them`: the events wait, the Receiver reads more slowly, and Fluent Bit keeps the records it
has read. An ERROR line `forward output: an event was not written`, `forward output closed with
events not written` or `forward output closed with events not delivered` names events the Receiver
did not hand back to Fluent Bit, which are lost. The HEC token is read by the second Fluent Bit
process only, and does not reach the Receiver or its log.

## Fields of the Original Sourcetype: `txf`

`tx` gives an expanded event the fields Splunk extracts from its text. The `txf` macro also
applies the search-time knowledge of the event's original sourcetype, as its add-on defines it:
field extractions, aliases, calculated fields, lookups, event types and tags. It is written where
`tx` goes:

```spl
index=wineventlog `txf` tag=authentication action=failure
index=wineventlog `txf(XmlWinEventLog)` EventCode=4625 | stats count by user
```

`txf(<sourcetype>)` applies the rules of that one sourcetype and starts faster. It returns the other compact events in range as well, without those rules, so where an index holds other sourcetypes, name the sourcetype too: `tenx_sourcetype=<sourcetype>` before the macro, or `sourcetype=<sourcetype>` after it. `txf` applies the
rules of every original sourcetype the app has recorded in the compact indexes, up to
`replay_max_sourcetypes` (tenx_config.conf), the busiest first. Where their rules would take more
commands than one Splunk search runs, or more characters than `replay_max_macro_chars` when it is
set, it holds the busiest sourcetypes, a `txf` search over an index that holds one of the others
shows a warning naming it, and `txf(<sourcetype>)` applies that sourcetype's rules.

When a `txf` search transforms its events (`stats`, `chart`, `timechart`, `top`, `rare`, `table`,
or `fields` naming the fields kept), `txf` applies only the rules that produce the fields the search
reads. It applies every rule in verbose mode, when the search returns events, and when it cannot tell
which fields the search reads.

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
[place the Receiver after the heavy forwarder's parsing](#receiver-beside-a-heavy-forwarder). The
same holds for the index-time rules of the original sourcetype on the indexers; `tenxreplay` names
such a mask in `masked_at_index_time`.

Through `txf`, a field whose name holds `*`, such as the JSON key `"a*"`, has each value twice on an
event the sender passed whole; on a compact event it is as on the raw event.

For FortiGate, the sender sets `tenx_sourcetype` to `fortigate_traffic`, `fortigate_utm`,
`fortigate_event` or `fortigate_anomaly` by the line's `type=`.

A compact event's `_time` is the first timestamp the Receiver found in the line. In a CloudTrail
record that can be `userIdentity.sessionContext.attributes.creationDate`, which comes before
`eventTime`.

A FortiGate line has its date and time in two fields, `date=` and `time=`; a compact FortiGate
event's `_time` is the line's own date and time.

A timestamp without a year takes its year from the time the event is processed, so a replayed or
backfilled file from an earlier year gets the wrong year. Splunk guesses the year for such lines
too, and the two guesses can differ. The Receiver sends an event of 65,535 characters or more whole, without a template: it is licensed at its full size, and its `_time` is the time its sender gave it rather than a time in its text (see [Events Sent as Text](#events-sent-as-text)).

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
  --csv report.csv
```

`--sourcetype` and `--index` name what moves, each as often as needed. Add `--tls-verify off`
for a management port with Splunk's default self-signed certificate, and `--app <app>` to report
one app. From files, `--dir` takes the place of `--splunkd`:

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
| limit | A shape this README lists as behaving differently on compact events; the reason quotes it |
| not classified | A macro the tool cannot expand, `map`, `savedsearch`, a subsearch that writes search terms, a dashboard token without a default, or a shape not measured |
| not affected | Reads none of the moved data |

Searches of compact events need `tx` or `txf`, except searches that count by index, host and
source. Data models and their accelerations read the original sourcetype's fields. A compact event
does not carry them, so data models do not count it. `tstats` reads the indexed sourcetype, which
on a compact event stays the compact one. A `tstats` search by or on the original sourcetype
therefore counts no compact events. The original sourcetype is in `tenx_sourcetype`, for example
`where (sourcetype=XmlWinEventLog OR tenx_sourcetype=XmlWinEventLog)`. A compact event indexed under
its original sourcetype, as
[Compact Events Under the Original Sourcetype](#compact-events-under-the-original-sourcetype)
describes, is read by `tstats` and the data models under that sourcetype, with the fields its
Receiver attached.

Checked on Splunk Enterprise 10.4.3 with the Windows add-on 12.0.0, the AWS add-on 8.3.1, the
FortiGate add-on 1.6.10 and CIM 8.8.0, on 117 saved searches, 18 of them ESCU detections, and two
dashboards over Windows Security, CloudTrail and FortiGate events, each run on the same events raw
and compact; the results are in the
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
| Search heads (through the deployer for a search head cluster) | the `_search_heads` package or the whole app, and the add-ons of the original sourcetypes |
| Indexers (through the cluster manager's bundle) | the `_indexers` package and the add-ons |
| Heavy forwarders that parse the compact events | the `_indexers` package and the add-ons |
| Universal Forwarders | nothing of 10x |

The whole app also works on indexers and heavy forwarders, and its scheduled searches then run
there with nothing to do. Replacing the whole app with the `_indexers` package on the indexers, or
the reverse, takes one rolling restart; updating the whole app in place takes none. The template
collection reaches the indexers in the knowledge bundle, so `tx` and `txf` need nothing more on
them. A template stored by Consume KV reaches them with the next bundle, about a minute later;
until then its events come back compact, with `tenx_expand_refused` set to `no-template`. For about
a minute after the app is installed on a search head, its template lookup has not reached the
indexers yet: a `tx` search then reads no event and says so; retry in a minute.

Consume KV writes the searchable copies of the templates with `collect` into the `tenx_dml` index,
as events of the search head it runs on. Create that index where the search head's own events are
indexed: on the search head, or on the indexers when the search head forwards its data to them.
Where it is missing, Splunk drops the copies with a warning in `splunkd.log`, and the search
rewrite (the `| tx` and `| tenxsearch` commands, the dashboard hook, compiled alerts) misses words
that only templates hold. The `tx` and `txf` macros read the KV store and do not use the copies.

### Receiver Beside a Heavy Forwarder

Where Universal Forwarders send to a heavy forwarder, the Receiver can run on the heavy forwarder's
host, and the Universal Forwarders stay as they are. The heavy forwarder parses the events with its
add-ons and writes the chosen sourcetypes to its ingest actions file destination, one JSON line per
event with its time, host, source, sourcetype and index. Fluent Bit reads those files, hands each
event to the Receiver, and writes what comes back to a folder of its own, again one JSON line per
event. The heavy forwarder reads that folder and sends the compact events to the indexers with its
own outputs, so the heavy forwarder's index-time rules apply before compaction, and no HTTP Event
Collector or token is needed. The steps are in the Log10x documentation:
[Receiver beside a heavy forwarder](https://doc.log10x.com/run/input/forwarder/splunkUF/#receiver-beside-a-heavy-forwarder).

The `_indexers` package holds the rule that reads those lines, `[tenx-record-unwrap]` in
`transforms.conf`. It gives each event back the host, source, index and time its line holds, sets
`tenx_sourcetype` to the original sourcetype, adds the line's `meta` text to its indexed fields, and
makes the compact text the event. `props.conf` runs it on the files under `/opt/tenx/compact/events/`.
For another folder, add a stanza for it to `local/props.conf` of the app on the heavy forwarder:

```
[source::<folder>/events/...]
TRANSFORMS-00_tenx_unwrap = tenx-relay-line, tenx-record-unwrap
```

Every compact event keeps the `_time` the heavy forwarder gave the raw event: the rule marks it
with the indexed field `tenx_time=sender`, and the app keeps the time of an event so marked, even
when its template has a timestamp slot. An HTTP Event Collector sender can set the same field. A
line the rule cannot read is indexed as it is, marked `tenx_unwrap=failed`. The route to the file
destination takes only events without `tenx_sourcetype`, so an event read back from the folder is
never routed again; route by sourcetype when a rule of the heavy forwarder's own sets the index
first.

In this arrangement the heavy forwarder parses the compact events: it takes the `_indexers` package
and the add-ons, and the indexers take only the indexes (`tenx_dml` and the compact indexes).

These limits apply to this arrangement:

- With indexer acknowledgement on the heavy forwarder's output (`useACK = true`), an indexer restart
  loses no compact event; a block whose acknowledgement is lost in the restart is sent again, and its
  events are indexed twice.
- A file of the folder deleted before the heavy forwarder has read it loses its events. The clean-up
  job in the documentation deletes only the files the heavy forwarder reports as finished reading.
- After the Receiver is stopped and started, Fluent Bit sends the records that waited on its retry
  schedule, whose wait between tries grows, so their compact events can arrive minutes after the
  Receiver is back.
- Fields a rule of the heavy forwarder's own writes with `WRITE_META` are not on the compact events.

### Universal Forwarder Relay Lines

Where a Universal Forwarder reads the Receiver's compact events from files, each line can carry the
fields the Receiver attaches and the event's time. Fluent Bit writes the file with `Format out_file`,
so a line is the record the Receiver returned, after its tag and time:

```
tenx.app.logs: [1794013200.448351000, {"event":"~...","meta":"user::\"bob\""}]
```

On the files under `/opt/tenx/compact/events/`, the instance that parses the events runs
`[tenx-relay-line]` and then `[tenx-record-unwrap]`. That instance is an indexer, or the heavy
forwarder the Universal Forwarder sends to. The event gets the line's time, marked `tenx_time=sender`,
and the record's `meta` text as indexed fields. The compact text becomes `_raw`, so only it is counted
against the licence. Files in another folder take the stanza shown above.

The record holds the compact text under `event`: Fluent Bit's tail input takes `Key event`, and the
Receiver `fluentbitInputMessageField event`. The Receiver writes the fields with `compactFieldsForm
text`, `compactFieldsKey meta` and `compactFieldsSeparator ::`. A `sourcetype` key in the record sets
`tenx_sourcetype`; without one, the event keeps the `tenx_sourcetype` of the monitor stanza's `_meta`.

Install the `_indexers` package on the parsing instance before Fluent Bit writes this format. Without
it, the whole line is indexed and counted against the licence, and nothing expands.

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

- `~`: Marks a compact event. A line without it is an event sent as its own text (see [Events Sent as Text](#events-sent-as-text))
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
^~(?<tenx_hash>[^,]+)(?:,(?<tenx_var_0>[^,]+)(?:,(?<tenx_vars>.*))?)?
```

- `~`: The tilde that starts every compact event; a line sent as text gets none of these fields
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
