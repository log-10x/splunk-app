# Log10x App

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Search and visualize [compact](https://doc.log10x.com/run/transform/#compact) events in Splunk with zero data loss. This open-source [Log10x](https://www.log10x.com/?utm_source=github&utm_medium=readme&utm_campaign=splunk-app&utm_content=hero) app expands compact events back to their original lines at search time, while the ingested volume, and with it the license bill, stays reduced. It runs on Splunk Enterprise 9.4 through 10.4, and the package passes AppInspect's Splunk Cloud checks.

> **Blog:** [Search compact logs in Splunk using the 10x app](https://www.log10x.com/blog/cutting-splunk-log-storage/?utm_source=github&utm_medium=readme&utm_campaign=splunk-app&utm_content=blog). How Splunk stores fewer bytes and still returns the original log lines.

To find optimization opportunities in your existing Splunk data, point the [Log10x MCP server](https://doc.log10x.com/apps/mcp/) at your Splunk backend with read-only credentials and ask it to run a cost POC. It pulls a representative sample via SPL, runs the 10x engine locally to rank message types, and returns a per-pattern cost and savings report with drop/compact/offload actions. Install with `claude mcp add --transport stdio --env LOG10X_API_KEY=your-api-key log10x -- npx -y log10x-mcp`.

## How It Works

A [compact event](https://doc.log10x.com/run/transform/#compact) carries a template hash and its variable values; the constant words live in the KV Store, and the app puts them back at search time. Classic dashboards keep their panel SPL unchanged: `dashboard.js` routes each panel's search through the app's REST endpoint. Splunk's search page loads no app JavaScript, so a query in the search bar, a saved search or the REST API is wrapped in the `tenxsearch` command. Scheduled alerts compile once at save time into native saved searches.

### Ingestion Flow

The [Receiver](https://doc.log10x.com/apps/receiver/) running in [Compact mode](https://doc.log10x.com/apps/receiver/compact/) [compacts](https://doc.log10x.com/run/transform/#compact) events at the edge, and Splunk ingests them at reduced size:

```
Receiver  -->  Ingest (UF/HEC)  -->  KV Store (Templates)
                                -->  Index (Encoded Events)
```

### Search Flow

Two paths reach the same rewrite, then [expand](https://doc.log10x.com/run/transform/#expand) the events:

```
Classic dashboard panel  -->  dashboard.js hook  --\
                                                   +-->  Transform (prefilter + macro)  -->  Expand  -->  Full results
Search bar | tenxsearch  --------------------------/
```

The dashboard path is the faster one: about 3 seconds for 20,000 expanded events, against about 21 seconds through the command, which writes every event out itself.

Scheduled alerts run server-side, where the browser hook never fires. They are instead **compiled once at save time** into native SPL, a template hash prefilter plus the inflate macro, so the scheduler runs an ordinary saved search. This is handled by the `/tenx-alert` REST endpoint and the **Compile Alert** view (with a recompile pass that converts `| tenxsearch` alerts and refreshes prefilters as templates appear). See [SAVE_TIME_ALERTS.md](SAVE_TIME_ALERTS.md).

## Receiver-side configuration

Set three options in the Receiver's configuration for any deployment that feeds this app.

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

**Set `maxPerObject: 1`** in the Receiver's timestamp configuration.

The Receiver records every timestamp it finds in an event as its own slot. This app stores one
timestamp format per template, so a template with two slots cannot render both. At `1` the first
timestamp keeps its slot and any later one becomes an ordinary variable whose text round-trips
unchanged.

### Store-time checks

Back-references and multi-timestamp templates are detected when stored. Their events stay compact
and carry `tenx_expand_refused` naming the reason, `back-reference` or `multiple-timestamps`, so
every expanded line is the original line. A Receiver's clock zone leaves no trace in the data, so
`timestampZone: UTC` is required rather than checked.

### Event time on compact events

A compact event's `_time` is the time Splunk indexed it, not the time in the original log
line. Measured on Splunk 10.4.3: `_time` equals `_indextime` for every event in the
compact index.

This matters when you search by time range. A search over the last hour selects events
that arrived in the last hour, and the lines they expand to may carry any timestamp. The
original time is in the event's first variable, as an epoch, and the expanded text shows it.

`_time` stays at index time because templates vary in whether they carry a timestamp and in
its precision, from milliseconds to nanoseconds, which one `TIME_FORMAT` cannot express.

## Quickstart

### Prerequisites

| Requirement | Description |
|-------------|-------------|
| Splunk Enterprise | 9.4 through 10.4 |
| Admin Access | Required for app installation and KV Store setup |

### Step 1: Install Splunk App

Install from Splunkbase, or clone the repository into your Splunk apps directory:

```bash
git clone https://github.com/log-10x/splunk-app.git
cp -r splunk-app/tenx-for-splunk $SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/bin/splunk restart
```

### Step 2: Create the Index and HEC Tokens

Create an index named `tenx_dml` for templates, then two HTTP Event Collector tokens: one for templates, one for compact events.

**Templates Token:**

| Setting | Value |
|---------|-------|
| Name | `tenx-templates` |
| Source type | `tenx_dml_raw_json` |
| Index | `tenx_dml` |

**Encoded Events Token:**

| Setting | Value |
|---------|-------|
| Name | `tenx-encoded` |
| Source type | `tenx_encoded` |
| Index | Your target index |

### Step 3: Configure the Receiver and Forwarder

Set `varMaxRecurIndexes: 0`, `timestampZone: UTC` and `maxPerObject: 1` in the Receiver's configuration (see [Receiver-side configuration](#receiver-side-configuration)), and point your forwarder at both tokens. See the [full documentation](https://doc.log10x.com/apps/receiver/compact/splunk/) for Fluent Bit, Fluentd, and OTel Collector examples.

### Step 4: Point the Dashboards at Your Index

Set the `tenx-events` macro to your compact index under **Settings > Advanced search > Search macros**, for example `index=my_compact_index sourcetype=tenx_encoded`.

### Step 5: Load Existing Templates

The **Consume KV** saved search stores new templates every five minutes. To load templates indexed before the app was installed, or during an outage of that search, run this search once as an admin or power user:

```spl
index=tenx_dml sourcetype=tenx_dml_raw_json earliest=-30d | sendalert tenx_dml_to_kv
```

Widen `earliest` to reach older templates. Running it again is safe: templates already stored are skipped. The app's **Backfill KV** saved search holds the same search; its alert action fires only when the search runs on a schedule or with `sendalert`, not from the **Run** button.

### Step 6: Verify End-to-End

Run these SPL queries to confirm everything is working:

**Check templates are arriving:**
```spl
index=tenx_dml sourcetype=tenx_dml_raw_json | head 10
```

**Check KV store is populated:**
```spl
| inputlookup tenx-dml-lookup | stats count
```

**Check compact events expand:**
```spl
| tenxsearch searchstring="index=your_logs_index sourcetype=tenx_encoded" | head 10
```

## Analytics Dashboard

The Analytics dashboard finds compact events through the `tenx-events` macro.

| Panel | Description |
|--------|-------------|
| **Total Encoded Events** | Compact events indexed |
| **Active Templates** | Templates in the KV Store |
| **Compression Ratio** | Original size over compact size |
| **Estimated Storage Savings** | Bytes saved and percentage reduction |
| **Event Volume, Last 7 Days** | Compact events per hour |
| **Top 10 Templates by Usage** | Template hashes with the most events |
| **Inflation Success Rate** | Share of sampled events that expand |

## Components

| Component | Description |
|-----------|-------------|
| **Search Hook** | `dashboard.js`, routing each classic dashboard panel's search to the Search Handler |
| **Search Handler** | `/tenx-search` REST endpoint rewriting a search for compact events |
| **tenxsearch Command** | Generating command for the search bar, saved searches and the REST API |
| **Alert Compiler** | `/tenx-alert` REST endpoint compiling a search into a native scheduled alert at save time (with a recompile/migrate pass) |
| **Compile Alert View** | UI to compile, review, and recompile save-time alerts |
| **KV Store** | Template patterns for event reconstruction |
| **Inflate Macro** | SPL macro joining events with templates |
| **Consume KV Search** | Scheduled search storing new templates in the KV Store |
| **Backfill KV Search** | The same template load over 30 days, for templates indexed before the app was installed |
| **Analytics Dashboard** | Compression and template metrics |
| **Diagnostics Dashboard** | Troubleshooting and verification tools |

## Documentation

For complete documentation including troubleshooting, advanced configuration, and integration guides, see:

- [Log10x App documentation](https://doc.log10x.com/apps/receiver/compact/splunk/)
- [Save-time alert compilation](SAVE_TIME_ALERTS.md): how scheduled alerts on compact data are compiled and kept current
- [Receiver Documentation](https://doc.log10x.com/apps/receiver/)
- [Log10x Documentation](https://doc.log10x.com/)

## License

This repository is licensed under the [MIT License](LICENSE).

### Important: Log10x Product License Required

This repository contains a Splunk app for expanding Log10x compact events. While the Splunk app itself is open source, **using the Log10x Receiver to compact events requires a commercial license**.

| Component | License |
|-----------|---------|
| This repository (Splunk app) | MIT (open source) |
| Log10x Receiver | Commercial license required |

**What this means:**
- You can freely use, modify, and distribute this Splunk app
- The Log10x Receiver that generates compact events requires a paid subscription
- A valid Log10x license is required to run the Receiver

**Get Started:**
- [Log10x Pricing](https://www.log10x.com/pricing?utm_source=github&utm_medium=readme&utm_campaign=splunk-app&utm_content=footer)
- [Documentation](https://doc.log10x.com)
- [Contact Sales](mailto:sales@log10x.com)

## Contributing

Contributions are welcome as pull requests to this repository.

## Support

For issues and feature requests:
- Open an issue on [GitHub](https://github.com/log-10x/splunk-app/issues)
- Contact the Log10x team at [support@log10x.com](mailto:support@log10x.com)
