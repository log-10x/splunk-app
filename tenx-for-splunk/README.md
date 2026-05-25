# 10x for Splunk - Log10x Log Optimization App

A Splunk app that enables search-time expansion of 10x compact log events. 10x replaces repetitive patterns with compact template hashes, achieving 50-80% storage reduction while maintaining full searchability.

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

### What does 10x for Splunk do?

The 10x for Splunk app provides the infrastructure to:

1. **Receive** template definitions from the 10x pipeline
2. **Store** parsed template data in a KV store for efficient lookup
3. **Inflate** compact events back to their original form at search time
4. **Search** compact data transparently using standard SPL queries

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
$($epoch) INFO [main] com.example.Service - Processing request for user $ with transaction id $
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
        | (runs every 2 min)     |                                    |
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
| KV Store (kvdml) |  | tenx_dml_pure     |                            |
| Template parts   |  | (searchable)     |                            |
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
| `tenx_dml_pure` | Searchable template patterns (hash + stripped pattern text) |
| `tenx_encoded` | Encoded log events in format: `~<hash>,<var0>,<var1>,...` |

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

#### Macros

| Macro | Purpose |
|-------|---------|
| `tenx-inflate` | Main inflation macro - reconstructs original events |
| `tenx-inflate-debug` | Same as above but keeps intermediate fields for debugging |
| `tenx-message(1)` | Utility macro to display messages in search results |

#### Python Scripts

| Script | Purpose |
|--------|---------|
| `tenx_dml_to_kv.py` | Alert action that populates KV store from template JSON |
| `tenx_dml_builder.py` | Core logic for parsing templates into KV-storable format |
| `tenx_util.py` | Utility functions (REST client, logging, config loading) |
| `tenx_consts.py` | Default configuration constants |
| `tenx_kv_intf.py` | KV store interface (get/create entries) |
| `tenx_dml_intf.py` | DML sourcetype interface (submit events) |

---

## Installation

### Prerequisites

- Splunk Enterprise 8.x or later
- Python 3.7+ (included with Splunk)
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
   - Confirm "10x for Splunk" appears in the app list

4. **Configure indexes (if needed):**
   - Create indexes for `tenx_dml_raw_json`, `tenx_dml_pure`, and `tenx_encoded` sourcetypes
   - Or use existing indexes by updating `tenx_config.conf`

### Directory Structure

```
tenx-for-splunk/
├── bin/                          # Python scripts
│   ├── tenx_consts.py            # Default configuration
│   ├── tenx_dml_builder.py       # Template parsing logic
│   ├── tenx_dml_intf.py          # DML sourcetype interface
│   ├── tenx_dml_to_kv.py         # Alert action entry point
│   ├── tenx_kv_intf.py           # KV store interface
│   └── tenx_util.py              # Utility functions
├── default/
│   ├── alert_actions.conf       # Alert action definition
│   ├── app.conf                 # App metadata
│   ├── collections.conf         # KV store schema
│   ├── tenx_config.conf          # App configuration
│   ├── tenx_config.conf.spec     # Configuration spec
│   ├── macros.conf              # SPL macros
│   ├── props.conf               # Sourcetype definitions
│   ├── savedsearches.conf       # Scheduled searches
│   └── transforms.conf          # Field extractions & lookups
├── lib/                         # Python libraries
└── metadata/
    └── default.meta             # Permissions
```

---

## Configuration

### Main Configuration (tenx_config.conf)

Located at `$SPLUNK_HOME/etc/apps/tenx-for-splunk/default/tenx_config.conf`:

```ini
[config]
# Index for processed template data
dest_dml_index = main

# Sourcetype for processed templates
dml_source_type = tenx_dml_pure

# KV store collection name
collection_name = kvdml

# Placeholder for timestamp in templates
timestamp_placeholder = __TENX_TS__

# Character separating variables in templates
variable_separator = $
```

### Modifying the Saved Search Schedule

The "Consume KV" saved search runs every 2 minutes by default. To adjust:

1. Navigate to Settings > Searches, reports, and alerts
2. Find "Consume KV" in the 10x for Splunk app
3. Edit the cron schedule as needed

Or modify `savedsearches.conf`:

```ini
[Consume KV]
cron_schedule = */2 * * * *      # Every 2 minutes
dispatch.earliest_time = -3m     # Look back 3 minutes
dispatch.latest_time = now
```

### Adding Custom Sourcetypes for Encoded Events

To use 10x with custom sourcetypes, add to `props.conf`:

```ini
[my_custom_sourcetype]
REPORT-tenx = tenx-hash-vars-extraction
```

This applies the field extraction that parses compact events into `tenx_hash`, `tenx_var_0`, and `tenx_vars` fields.

---

## Usage

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

### Step 2: Verify Template Ingestion

After sending some test data, verify templates are being received:

```spl
index=* sourcetype=tenx_dml_raw_json earliest=-15m
| head 10
```

### Step 3: Check KV Store Population

Wait 2-3 minutes for the "Consume KV" saved search to run, then verify:

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

- `~` - Optional prefix (handled by extraction regex)
- `<hash>` - Template hash identifier
- `<var0>` - First variable (typically epoch timestamp in milliseconds or nanoseconds)
- `<var1>...` - Additional variable values

### Template Format

Templates use `$` as the variable separator:

```
$ INFO [main] MyService - User $ performed action $ at $
```

Special timestamp format:
```
$(<format>) - Timestamp placeholder with Java SimpleDateFormat pattern
$(epoch) - Special case for milliseconds since epoch
```

Examples:
- `$(yyyy-MM-dd'T'HH:mm:ss.SSS'Z')` - ISO 8601 format
- `$(epoch)` - Unix epoch milliseconds

### Expansion Macro Logic

The `tenx-inflate` macro performs these operations:

1. **Parse variables**: `makemv delim="," tenx_vars`
   - Converts comma-separated variable string to multivalue field

2. **Lookup template**: `lookup tenx-dml-lookup _key AS tenx_hash`
   - Retrieves template parts from KV store

3. **Detect timestamp precision**:
   ```
   eval tenx_ts_sec = if(tenx_var_0 > 10000000000000,
                        tenx_var_0 / 1000000000,    # nanoseconds
                        tenx_var_0 / 1000)          # milliseconds
   ```

4. **Reconstruct event**: Combines template parts with variables using `mvzip` and `mvappend`

5. **Format timestamp**: Replaces `__TENX_TS__` placeholder with formatted time using `strftime`

6. **Cleanup**: Removes intermediate `tenx_*` fields

### Field Extraction Regex

The `tenx-hash-vars-extraction` transform:

```regex
^~?(?<tenx_hash>[^,]+),(?<tenx_var_0>[^,]+)(?:,(?<tenx_vars>.*))?
```

- `~?` - Optional tilde prefix
- `(?<tenx_hash>[^,]+)` - Capture hash (everything up to first comma)
- `(?<tenx_var_0>[^,]+)` - Capture first variable (timestamp)
- `(?:,(?<tenx_vars>.*))?` - Optionally capture remaining variables

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
| `/services/receivers/simple` | Submit events to index |

---

## Troubleshooting

### Dashboard Shows "No Results Found"

This is a common issue when dashboard panels using the `search` command return empty while API queries work. The root causes and solutions are documented below.

#### Time Range Issues

**Problem**: Dashboard search time ranges behave differently than API searches.

**Solutions**:
1. **Use `<earliest>1</earliest>` instead of `<earliest>0</earliest>`**
   - In dashboards, `earliest=0` may be interpreted as "no time constraint" rather than "epoch 0"
   - Using `1` (epoch second 1, Jan 1 1970 00:00:01) works reliably

2. **Leave `<latest>` empty rather than `now`**
   ```xml
   <!-- CORRECT -->
   <earliest>1</earliest>
   <latest></latest>

   <!-- PROBLEMATIC -->
   <earliest>0</earliest>
   <latest>now</latest>
   ```

#### Index Specification Issues

**Problem**: `index=*` in dashboard context may not search all indexes.

**Solution**: Always specify explicit index names:
```spl
<!-- CORRECT -->
index=tenx_encoded

<!-- PROBLEMATIC -->
index=* sourcetype=tenx_encoded
```

#### Subsearch Limitations

**Problem**: `appendpipe [| tstats ...]` and similar subsearch patterns fail silently in dashboard context.

**Solution**: Simplify queries to avoid subsearches. Use `untable` instead of complex append patterns:
```spl
<!-- CORRECT - Use untable for pivoting -->
| stats sum(enc) as enc, sum(inf) as inf
| eval Encoded=round(enc/1048576, 2), Original=round(inf/1048576, 2)
| fields Encoded, Original
| untable _row metric MB

<!-- PROBLEMATIC - appendpipe fails in dashboards -->
| appendpipe [| tstats count where index=tenx_encoded | ...]
```

#### tstats vs search Command

**Problem**: `tstats` works but `search` returns nothing.

**Explanation**:
- `tstats` searches tsidx (index metadata) - faster, always available
- `search` searches raw events - requires correct index/time range permissions

**Diagnostic approach**:
```spl
<!-- Test 1: Does tstats find data? -->
| tstats count where index=tenx_encoded

<!-- Test 2: What indexes have data? -->
| eventcount summarize=false index=*

<!-- Test 3: What's the time range of data? -->
index=tenx_encoded | stats min(_time) as earliest, max(_time) as latest
| eval earliest=strftime(earliest, "%Y-%m-%d"), latest=strftime(latest, "%Y-%m-%d")
```


### Templates Not Appearing in KV Store

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

Copyright (c) Log10x. All rights reserved.

---

## Support

For issues and feature requests, contact the Log10x team.
