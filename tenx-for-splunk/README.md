# Log10x App

Search-time expansion of 10x compact log events, for Splunk Enterprise 9.4 through 10.6. The package passes AppInspect's Splunk Cloud checks. 10x replaces repetitive patterns with compact template hashes, cutting stored volume while maintaining full searchability.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
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

1. **Receive** template definitions from the 10x pipeline
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
~abc123def,1705315845123,john_doe,TX-789012
```

**Template stored in KV store:**
```
$(epoch) INFO [main] com.example.Service - Processing request for user $ with transaction id $
```

At search time, the `tenx-inflate` macro reconstructs the original event by combining the template with the variable values.

---

## Architecture

### Data Flow

```
                                    +------------------+
                                    |   10x Pipeline   |
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

---

## Installation

### Prerequisites

- Splunk Enterprise 9.4 through 10.6
- Python 3.9 or later, as shipped with those versions of Splunk
- Admin access to install apps

### Installation Steps

1. **Copy the app to Splunk:**
   ```bash
   cp -r tenx-for-splunk $SPLUNK_HOME/etc/apps/
   ```

2. **Restart Splunk:**
   ```bash
   $SPLUNK_HOME/bin/splunk restart
   ```

3. **Verify installation:**
   - Navigate to Settings > Apps in Splunk Web
   - Confirm "Log10x App" appears in the app list

4. **Create the template index:**
   - Create an index named `tenx_dml`. Templates arrive there as `tenx_dml_raw_json`, and their
     searchable copy is written there with `collect` (sourcetype `stash`, source `tenx_dml_pure`),
     which is not licence-metered. Compact events (`tenx_encoded`) go to any index.

5. **Point the dashboards at your compact index:** set the `tenx-events` macro, see
   [Pointing the Dashboards at Your Compact Events](#pointing-the-dashboards-at-your-compact-events).

6. **Load templates already indexed:** run the backfill search once, see
   [Loading Templates Indexed Earlier](#loading-templates-indexed-earlier).

### Directory Structure

```
tenx-for-splunk/
├── appserver/static/            # dashboard.js, the search hook, the Compile Alert script
├── bin/                         # Python scripts, see Python Scripts above
├── default/
│   ├── alert_actions.conf       # Alert action definition
│   ├── app.conf                 # App metadata
│   ├── collections.conf         # KV store schema
│   ├── commands.conf            # The tenxprefilter, tx, tenxsearch and tenxrecompile commands
│   ├── macros.conf              # SPL macros, including tx
│   ├── props.conf               # Sourcetype definitions
│   ├── restmap.conf, web.conf   # The /tenx-search and /tenx-alert endpoints
│   ├── savedsearches.conf       # Consume KV, Backfill KV, Recompile Compiled Alerts
│   ├── tenx_config.conf         # App configuration
│   ├── transforms.conf          # Field extractions and lookups
│   └── data/ui/                 # Dashboards and navigation
├── lib/                         # splunklib and parsimonious, see THIRD_PARTY_NOTICES
├── metadata/
│   └── default.meta             # Permissions
├── README/
│   └── tenx_config.conf.spec    # Configuration spec
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
dispatch.earliest_time = -7m
dispatch.latest_time = now
```

Keep the window wider than the interval, or a template that arrives between two runs is
never stored.

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
button does not fire its alert action, so run the search above.

### Adding Custom Sourcetypes for Encoded Events

To use 10x with custom sourcetypes, add to `props.conf`:

```ini
[my_custom_sourcetype]
REPORT-tenx = tenx-hash-vars-extraction
```

This applies the field extraction that parses compact events into `tenx_hash`, `tenx_var_0`, and `tenx_vars` fields.

### Pointing the Dashboards at Your Compact Events

The app's Analytics and Diagnostics dashboards read the `tenx-events` macro. Its default,
`index=* sourcetype=tenx_encoded`, finds the app's sourcetype in every index you can search.
Set it to your compact index, and add any custom sourcetype, under **Settings > Advanced
search > Search macros**:

```spl
index=my_compact_index (sourcetype=tenx_encoded OR sourcetype=my_custom_sourcetype)
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
`field=value`, `field IN (...)`, wildcards, `TERM()`, `CASE()`, `NOT`, `OR`, `AND` and
parentheses behave as on the original data, with Splunk's precedence. The fields are the ones
Splunk extracts from the original lines, key=value pairs and JSON alike. Searching an IP address, a hostname or an ID works the
same way: the words go after `tx`, whether they are values or template text.

**Classic dashboards.** `dashboard.js` loads on every classic dashboard in the app that
carries it and routes the panel's search through the app's REST endpoint. Panels keep
their SPL. To cover another app's dashboards, copy the file into that app's
`appserver/static/` and restart.

**Rules.**

- Time modifiers (`earliest=`, `latest=`) go before `tx`. After it they would match no
  event, so the search stops with a message saying so.
- A comma outside quotes after `tx` is matched literally by Splunk, so the search stops with
  a message. Remove the comma, or put the text in quotes.
- The index, sourcetype, host and the forwarder's indexed fields narrow what is read when
  they come before `tx`. After it they filter the expanded events, which gives the same
  result more slowly.
- `tx` inside another subsearch (`append`, `join`) or wrapped in another macro cannot read
  its own words. It then expands every compact event in range and applies the words after,
  with a warning: the same result, more slowly.
- A compact event is the event the 10x engine formed. Lines without a timestamp of their
  own, such as the lines of a stack trace, join the line before them, so a stack trace is
  one event, a count counts events, and words joined with AND can match on different lines
  of one event.

**How `tx` chooses the events to expand.** Its subsearch runs `tenxprefilter` once per
search. The command reads the search's own text, takes the words after `tx`, finds which
templates carry each word, and selects the compact events that carry each word as a value
or through their template. A word a rendered timestamp could print, a word with a character
outside a-z and 0-9, and a word carried by more than 5,000 templates select nothing on their
own, and a `NOT`, a field comparison, or an `OR` with any of these selects every event in
range. The search after `tx` then applies the full terms, so the selection may be wider than
the result, never narrower.

**The `tx` and `tenxsearch` commands.** `| tx index=myindex sourcetype=tenx_encoded error`
and `| tenxsearch searchstring="..."` run a rewritten search and write every event out
through Python, which is several times slower than the macro. They are kept so saved
searches written with them keep working.

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

## Getting Started

### Step 1: Configure Your 10x Pipeline

Configure your 10x pipeline to output:

1. **Templates** to a Splunk HTTP Event Collector (HEC) or file input with:
   - Sourcetype: `tenx_dml_raw_json`
   - Format: `{"templateHash":"<hash>", "template":"<pattern>"}`

2. **Encoded events** with:
   - Sourcetype: `tenx_encoded`
   - Format: `~<hash>,<var0>,<var1>,...`

3. **Receiver settings** this app relies on: `varMaxRecurIndexes: 0`, `timestampZone: UTC`
   and `maxPerObject: 1`. The [repository README](https://github.com/log-10x/splunk-app/blob/main/README.md#receiver-side-configuration)
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

Search for compact events and expand:

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
^~?(?<tenx_hash>[^,]+),(?<tenx_var_0>[^,]+)(?:,(?<tenx_vars>.*))?
```

- `~?`: Optional tilde prefix
- `(?<tenx_hash>[^,]+)`: Capture hash (everything up to first comma)
- `(?<tenx_var_0>[^,]+)`: Capture first variable (timestamp)
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
   | spath
   | table templateHash, template
   ```

### A `tx` Search Returns No Results

- **The time range comes after `tx`.** Move `earliest=` and `latest=` before it; in the
  search bar the job stops with a message that says so.
- **The search goes through the REST export endpoint.** `/services/search/jobs/export`
  drops the message of a command that fails inside a subsearch and returns no rows. Run the
  search through `/services/search/jobs` to read the message.
- **The words belong to a template stored in the last few minutes.** Wait for the next
  Consume KV run, or run it by hand (Settings > Searches, reports, and alerts).

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
