# 10x for Splunk

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Search and visualize [compact](https://doc.log10x.com/run/transform/#compact) events in Splunk with zero data loss. This open-source [Log10x](https://www.log10x.com/?utm_source=github&utm_medium=readme&utm_campaign=splunk-app&utm_content=hero) app transparently expands compact events at search time, maintaining full querying, dashboard, and alerting capabilities while reducing ingested volume, and with it the license bill.

> **Blog:** [Search compact logs in Splunk using the 10x app](https://www.log10x.com/blog/cutting-splunk-log-storage/?utm_source=github&utm_medium=readme&utm_campaign=splunk-app&utm_content=blog). How Splunk stores fewer bytes and still returns the original log lines.

To find optimization opportunities in your existing Splunk data, point the [Log10x MCP server](https://doc.log10x.com/apps/mcp/) at your Splunk backend with read-only credentials and ask it to run a cost POC. It pulls a representative sample via SPL, runs the 10x engine locally to rank message types, and returns a per-pattern cost and savings report with drop/compact/offload actions. Install with `claude mcp add --transport stdio --env LOG10X_API_KEY=your-api-key log10x -- npx -y log10x-mcp`.

## How It Works

The app intercepts search requests and automatically expands [compact events](https://doc.log10x.com/run/transform/#compact) before displaying results. Users interact with Splunk exactly as before - searching, building dashboards, and configuring alerts on the original full-fidelity data.

### Ingestion Flow

Events are [compacted](https://doc.log10x.com/run/transform/#compact) at the edge by the [Receiver](https://doc.log10x.com/apps/receiver/) running in [Compact mode](https://doc.log10x.com/apps/receiver/compact/) and ingested into Splunk with reduced payload size:

```
Receiver  -->  Ingest (UF/HEC)  -->  KV Store (Templates)
                                -->  Index (Encoded Events)
```

### Search Flow

Interactive searches are transparently transformed to [expand](https://doc.log10x.com/run/transform/#expand) compact events via a browser hook:

```
User Search  -->  Hook Intercept  -->  Transform (Add Macro)  -->  Inflate (Decode)  -->  Full Results
```

Scheduled alerts run server-side, where the browser hook never fires. They are instead **compiled once at save time** into native SPL, a template hash prefilter plus the inflate macro, so the scheduler runs an ordinary saved search. This is handled by the `/tenx-alert` REST endpoint and the **10x Compile Alert** view (with a recompile pass that migrates legacy alerts and refreshes prefilters as templates appear). See [SAVE_TIME_ALERTS.md](SAVE_TIME_ALERTS.md).

## Receiver-side configuration

This app does not decode template **back-references** (`$N` syntax, produced when the Receiver's
[`varMaxRecurIndexes`](https://doc.log10x.com/run/template/#varmaxrecurindexes) setting reuses an
earlier variable value instead of re-encoding it). It has no value to put there.

Such a template is detected when it is stored and marked `expand_unsafe`. The inflate macro then
leaves the compact event as it is and sets `tenx_expand_refused` on the result, rather than
printing text that is not the original line. Earlier versions expanded it anyway and returned the
wrong text silently, since the search still returned a result.

**Set `varMaxRecurIndexes: 0`** in the Receiver's pipeline configuration for any deployment that
feeds this app. This is a whole-process setting, not a per-destination one: disabling it costs a
small amount of the modeled compression (roughly half a percentage point, measured on a realistic
Kubernetes/OTel corpus), in exchange for correct expansion of every event.

### Timestamps

**Set `timestampZone: UTC`** in the Receiver's pipeline configuration as well.

A timestamp that carries no zone marker of its own, `2025-10-02 06:35:34,498`,
is only a time once something decides which zone it was written in. The Receiver
decides, and by default it uses the clock of the host it runs on. That choice is
not recorded in the compact event, so this app cannot recover it: the same line
compacted on a host in New York and on a host in UTC produces two different
events, and nothing downstream can tell them apart.

Pinning the Receiver to UTC makes that choice fixed and knowable, and this app's
inflate macro renders in UTC to match. Without it, expansion returns a time
shifted by the difference between the Receiver's host clock and UTC.

Timestamps that do carry their own zone, anything ending in `Z` or an offset,
are unaffected either way.

**If the same Receiver also feeds Elasticsearch** in a fan-out topology, this setting applies to
that traffic too. That is not a correctness problem for Elasticsearch, because the
[elasticsearch-plugin](https://github.com/log-10x/elasticsearch-plugin) decoder handles
back-references correctly. It means only that the Elasticsearch traffic forgoes the same small
compression gain for as long as the Receiver instance it shares with Splunk has this setting
disabled.

### One timestamp per event

**Set `maxPerObject: 1`** in the Receiver's timestamp configuration.

The Receiver records every timestamp it finds in an event as its own slot. This app stores one
timestamp format per template and reconstructs one, so a template carrying two slots can only
render one of them, and the one it renders is not the one the format describes. At `1` the first
timestamp keeps its slot and any later one becomes an ordinary variable whose literal text
round-trips unchanged.

A template with more than one slot is detected when it is stored and refused in the same way as a
back-reference, so the failure is visible rather than silent.

### What happens if these are not set

Nothing is expanded wrongly. Both back-references and multi-timestamp templates are detected at
store time, and the macro declines to expand the events that use them, leaving the compact text
and a `tenx_expand_refused` field naming the reason. The cost of missing a setting is events that
do not expand, not events that expand to the wrong text. The zone setting is the exception: a
Receiver on a non-UTC clock cannot be detected from the data, which is why it is pinned rather
than checked.

## Quickstart

### Prerequisites

| Requirement | Description |
|-------------|-------------|
| Splunk Enterprise | 9.4 through 10.4 |
| Admin Access | Required for app installation and KV Store setup |

### Step 1: Install Splunk App

Clone the repository and install to your Splunk apps directory:

```bash
git clone https://github.com/log-10x/splunk-app.git
cp -r splunk-app/tenx-for-splunk $SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/bin/splunk restart
```

### Step 2: Create HEC Tokens

Create two HTTP Event Collector tokens in Splunk - one for templates, one for compact events.

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
| Source type | Select appropriate for your logs |
| Index | Your target index |

### Step 3: Configure Forwarder

Configure your log forwarder to send compact events and templates to Splunk. See the [full documentation](https://doc.log10x.com/apps/receiver/compact/splunk/) for Fluent Bit, Fluentd, and OTel Collector examples.

### Step 4: Verify End-to-End

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
index=your_logs_index | head 10
```

## Analytics Dashboard

The app includes a built-in analytics dashboard providing real-time visibility into optimization performance, storage savings, and ROI metrics.

| Metric | Description |
|--------|-------------|
| **Total Encoded Events** | Count of optimized events ingested |
| **Active Templates** | Number of unique patterns in KV Store |
| **Reduction Ratio** | Average reduction factor across all events |
| **Storage Savings** | Estimated bytes saved and percentage reduction |
| **Event Volume Over Time** | Trend comparison of compact vs original volume |
| **Top Templates by Usage** | Most frequently matched patterns |
| **Expansion Success Rate** | Percentage of events successfully expanded |

## Components

| Component | Description |
|-----------|-------------|
| **Search Hook** | JavaScript module intercepting all search requests |
| **Search Handler** | REST endpoint transforming SPL queries |
| **Alert Compiler** | `/tenx-alert` REST endpoint compiling a search into a native scheduled alert at save time (with a recompile/migrate pass) |
| **Compile Alert View** | UI to compile, review, and recompile save-time alerts |
| **KV Store** | Template patterns for event reconstruction |
| **Inflate Macro** | SPL macro joining events with templates |
| **Consume KV Search** | Scheduled search populating KV store from templates |
| **Analytics Dashboard** | Compression metrics and ROI visualization |
| **Diagnostics Dashboard** | Troubleshooting and verification tools |

## Documentation

For complete documentation including troubleshooting, advanced configuration, and integration guides, see:

- [10x for Splunk Documentation](https://doc.log10x.com/apps/receiver/compact/splunk/)
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

Contributions are welcome! Please read our contributing guidelines and submit pull requests to the repository.

## Support

For issues and feature requests:
- Open an issue on [GitHub](https://github.com/log-10x/splunk-app/issues)
- Contact the Log10x team at [support@log10x.com](mailto:support@log10x.com)
