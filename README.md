# 10x for Splunk

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Search and visualize [10x-encoded](https://doc.log10x.com/run/transform/#encoding) events in Splunk with zero data loss. This open-source app transparently decodes encoded events at search time, maintaining full querying, dashboard, and alerting capabilities while reducing ingestion costs by over 50%.

Use the [Cloud Reporter](https://doc.log10x.com/apps/cloud/reporter/) to identify optimization opportunities in your existing Splunk data.

## How It Works

The app intercepts search requests and automatically inflates [encoded events](https://doc.log10x.com/run/transform/#encoding) before displaying results. Users interact with Splunk exactly as before - searching, building dashboards, and configuring alerts on the original full-fidelity data.

### Ingestion Flow

Events are [encoded](https://doc.log10x.com/run/transform/#encoding) at the edge by the [Edge Optimizer](https://doc.log10x.com/apps/edge/optimizer/) and ingested into Splunk with reduced payload size:

```
Optimizer  -->  Ingest (UF/HEC)  -->  KV Store (Templates)
                                 -->  Index (Encoded Events)
```

### Search Flow

Searches are transparently transformed to [inflate](https://doc.log10x.com/run/transform/#decoding) encoded events:

```
User Search  -->  Hook Intercept  -->  Transform (Add Macro)  -->  Inflate (Decode)  -->  Full Results
```

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

Create two HTTP Event Collector tokens in Splunk - one for templates, one for encoded events.

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

Configure your log forwarder to send encoded events and templates to Splunk. See the [full documentation](https://doc.log10x.com/apps/edge/optimizer/splunk/) for Fluent Bit, Fluentd, and OTel Collector examples.

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

**Check encoded events inflate:**
```spl
index=your_logs_index | head 10
```

## Analytics Dashboard

The app includes a built-in analytics dashboard providing real-time visibility into optimization performance, storage savings, and ROI metrics.

| Metric | Description |
|--------|-------------|
| **Total Encoded Events** | Count of optimized events ingested |
| **Active Templates** | Number of unique patterns in KV Store |
| **Compression Ratio** | Average reduction factor across all events |
| **Storage Savings** | Estimated bytes saved and percentage reduction |
| **Event Volume Over Time** | Trend comparison of encoded vs original volume |
| **Top Templates by Usage** | Most frequently matched patterns |
| **Inflation Success Rate** | Percentage of events successfully decoded |

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

- [10x for Splunk Documentation](https://doc.log10x.com/apps/edge/optimizer/splunk/)
- [Edge Optimizer Documentation](https://doc.log10x.com/apps/edge/optimizer/)
- [Log10x Documentation](https://doc.log10x.com/)

## License

This repository is licensed under the [Apache License 2.0](LICENSE).

### Important: Log10x Product License Required

This repository contains a Splunk app for decoding Log10x-encoded events. While the Splunk app itself is open source, **using the Log10x Edge Optimizer to encode events requires a commercial license**.

| Component | License |
|-----------|---------|
| This repository (Splunk app) | Apache 2.0 (open source) |
| Log10x Edge Optimizer | Commercial license required |

**What this means:**
- You can freely use, modify, and distribute this Splunk app
- The Log10x Edge Optimizer that generates encoded events requires a paid subscription
- A valid Log10x license is required to run the Edge Optimizer

**Get Started:**
- [Log10x Pricing](https://log10x.com/pricing)
- [Documentation](https://doc.log10x.com)
- [Contact Sales](mailto:sales@log10x.com)

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to the repository.

## Support

For issues and feature requests:
- Open an issue on [GitHub](https://github.com/log-10x/splunk-app/issues)
- Contact the Log10x team at [support@log10x.com](mailto:support@log10x.com)
