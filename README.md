# 10x for Splunk

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Search and visualize [compact](https://doc.log10x.com/run/transform/#compact) events in Splunk with zero data loss. This open-source [Log10x](https://www.log10x.com/?utm_source=github&utm_medium=readme&utm_campaign=splunk-app&utm_content=hero) app transparently expands compact events at search time, maintaining full querying, dashboard, and alerting capabilities while reducing ingestion costs by over 50%.

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

Searches are transparently transformed to [expand](https://doc.log10x.com/run/transform/#expand) compact events:

```
User Search  -->  Hook Intercept  -->  Transform (Add Macro)  -->  Inflate (Decode)  -->  Full Results
```

## Receiver-side configuration

This app does not decode template **back-references** (`$N` syntax, produced when the Receiver's
[`varMaxRecurIndexes`](https://doc.log10x.com/run/template/#varmaxrecurindexes) setting reuses an
earlier variable value instead of re-encoding it). If a compact event's template uses a
back-reference, the app's inflate macro currently reconstructs the wrong text for that value —
silently, since the search still returns a result, just not the original one.

**Set `varMaxRecurIndexes: 0`** in the Receiver's pipeline configuration for any deployment that
feeds this app. This is a whole-process setting, not a per-destination one: disabling it costs a
small amount of the modeled compression (roughly half a percentage point, measured on a realistic
Kubernetes/OTel corpus), in exchange for correct expansion of every event.

**If the same Receiver also feeds ClickHouse or Elasticsearch** in a fan-out topology, this
setting applies to that traffic too. That is not a correctness problem for those destinations —
the [clickhouse-app](https://github.com/log-10x/clickhouse-app) and
[elasticsearch-plugin](https://github.com/log-10x/elasticsearch-plugin) decoders already handle
back-references correctly — it just means they forgo the same small compression gain for as long
as the Receiver instance they share with Splunk has this setting disabled.

## Quickstart

### Prerequisites

| Requirement | Description |
|-------------|-------------|
| Splunk Enterprise | Version 8.0 or later |
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
| **KV Store** | Template patterns for event reconstruction |
| **Inflate Macro** | SPL macro joining events with templates |
| **Consume KV Search** | Scheduled search populating KV store from templates |
| **Analytics Dashboard** | Compression metrics and ROI visualization |
| **Diagnostics Dashboard** | Troubleshooting and verification tools |

## Documentation

For complete documentation including troubleshooting, advanced configuration, and integration guides, see:

- [10x for Splunk Documentation](https://doc.log10x.com/apps/receiver/compact/splunk/)
- [Receiver Documentation](https://doc.log10x.com/apps/receiver/)
- [Log10x Documentation](https://doc.log10x.com/)

## License

This repository is licensed under the [Apache License 2.0](LICENSE).

### Important: Log10x Product License Required

This repository contains a Splunk app for expanding Log10x compact events. While the Splunk app itself is open source, **using the Log10x Receiver to compact events requires a commercial license**.

| Component | License |
|-----------|---------|
| This repository (Splunk app) | Apache 2.0 (open source) |
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
