# Splunkbase listing: Log10x App

The text for each field of the Splunkbase submission form, in the order the form asks for
it. Paste each block as written. The package is built from `tenx-for-splunk/` with the
command at the end of this file.

## Basic information

| Field | Value |
|---|---|
| App name | Log10x App |
| Author | Log10x |
| Hosting | Splunkbase will host my app |
| Access level | Anyone can download the app |
| Content type | App |

The app name must match `[ui] label` in `default/app.conf` exactly.

## Legal information

| Field | Value |
|---|---|
| End-user license | Other: MIT License, https://github.com/log-10x/splunk-app/blob/main/LICENSE |
| Export control | The package contains no encrypted code |

## App description

**Summary**

> With the Log10x App, Splunk can index compact log events and still search, chart and alert
> on the original lines. The 10x Receiver stores each event as a template hash plus the values
> that change, so a stream of repeated patterns takes less of the license. On the OpenTelemetry
> demo the bytes sent to Splunk shrank by 63.7%, encoded events and template dictionary counted
> together, and every line expanded back byte-identical with the Receiver settings in the
> installation steps (measurement: https://www.log10x.com/blog/cutting-splunk-log-storage/).
> The same license then holds more: sources that were sampled, filtered or kept out of Splunk
> to stay under the limit can come back, or the license can be smaller.
>
> Classic dashboards keep their SPL: the browser sends each panel's search to the app, which
> rewrites it on the server. From the search bar, saved searches, alerts and the REST API, a
> search is wrapped in the `tenxsearch` command. An alert created in the app's Compile Alert
> view is compiled once into a native saved search, so the scheduler runs no Python. NOT, OR,
> groups, phrases, field conditions, and values such as IP addresses and hostnames behave as
> they do on the original data.
>
> The 10x Receiver produces compact events, and it is free on up to 10 nodes
> (https://www.log10x.com/pricing). No sign-up is
> required to evaluate it: with no license token it runs the full product for 30 days on up to
> 10 nodes, air-gapped, and a free license removes the time limit
> (https://doc.log10x.com/manage/license/). The app
> itself is open source under the MIT license.

**Short description**

> Send Splunk the logs that sampling and filters keep out to fit the license, on that same
> license. Compact events take a fraction of the volume and expand back byte-identical at
> search time; classic dashboards keep their SPL, and one command covers the search bar, saved
> searches, alerts and the REST API.

**Details**

> **Two ways to search compact events**
>
> - Classic dashboards: `dashboard.js` routes each panel's search through the app's REST
>   endpoint, which rewrites it. Panels keep their SPL. Copy the file into another app's
>   `appserver/static/` to cover that app's dashboards.
> - Everywhere else: `| tenxsearch searchstring="index=my_index sourcetype=tenx_encoded error"`.
>   Escape a quoted phrase inside the wrapper: `searchstring="index=my_index \"payment failed\""`.
>
> **Dashboards**
>
> Analytics shows compact event counts, active templates, compression ratio and storage
> saved. Diagnostics checks each stage from template arrival to expansion. Both find compact
> events through the `tenx-events` macro.
>
> **Search coverage**
>
> - Outside a classic dashboard, a search without the `tenxsearch` command returns zero
>   events or unexpanded `~hash,...` rows, not an error.
> - A search the app cannot rewrite is refused with a message. The rewrite refuses one
>   shape: a sourcetype inside an OR with other terms, `sourcetype=x OR host=y`.
> - Dashboard Studio loads no app JavaScript; its panels use the command.
> - A compact event's `_time` is its index time; the original timestamp is in the expanded line.
>
> **Speed**, 20,000 expanded events on Splunk 10.4.3: about 3 seconds through a dashboard,
> about 21 seconds through the command, which writes every event out itself.
>
> **Network**: the app makes no outbound calls. It talks only to the local splunkd.
>
> Full documentation: https://doc.log10x.com/apps/receiver/compact/splunk/
>
> How it works, with the measurement: https://www.log10x.com/blog/cutting-splunk-log-storage/

**Installation**

> 1. Install the app and restart Splunk.
> 2. Create an index named `tenx_dml` for templates. The app stores each template there a
>    second time, as `tenx_dml_pure`, for search.
> 3. Create two HTTP Event Collector tokens: one with sourcetype `tenx_dml_raw_json` and
>    index `tenx_dml` for templates, one with sourcetype `tenx_encoded` and your index for
>    compact events.
> 4. Deploy the 10x Receiver (https://doc.log10x.com/apps/receiver/deploy/) and point it at
>    both tokens, with `varMaxRecurIndexes: 0`, `timestampZone: UTC` and `maxPerObject: 1` in
>    its configuration.
> 5. Set the `tenx-events` macro to your compact index: Settings > Advanced search > Search
>    macros, for example `index=my_compact_index sourcetype=tenx_encoded`.
> 6. If templates were indexed before the app was installed, run this search once:
>    `index=tenx_dml sourcetype=tenx_dml_raw_json earliest=-30d | sendalert tenx_dml_to_kv`
>
> After upgrading the app, restart Splunk so Splunk Web serves the updated dashboard script.
>
> Step-by-step guide: https://doc.log10x.com/apps/receiver/compact/splunk/

**Troubleshooting**

> - **Dashboards show zero events.** Set the `tenx-events` macro to the index and sourcetype
>   your compact events use.
> - **A search returns zero events.** Wrap it in `| tenxsearch searchstring="..."`, or run it
>   from a classic dashboard in an app that carries `dashboard.js`.
> - **A search is refused.** The message names the cause; the detail is in
>   `$SPLUNK_HOME/var/log/splunk/tenx_search_command.log` or `tenx_search_handler.log`.
> - **Events show as `~hash,value,...`.** The template has not reached the KV Store yet. The
>   Consume KV saved search runs every five minutes; the Diagnostics dashboard shows its runs.
>   Templates indexed before the app was installed need one run of
>   `index=tenx_dml sourcetype=tenx_dml_raw_json earliest=-30d | sendalert tenx_dml_to_kv`.
> - **An event stays compact and carries `tenx_expand_refused`.** Its template cannot be
>   expanded exactly. `back-reference` means the Receiver needs `varMaxRecurIndexes: 0`;
>   `multiple-timestamps` means it needs `maxPerObject: 1`.
> - **Behavior unchanged after an upgrade.** Restart Splunk so Splunk Web serves the new
>   dashboard script.

**Categories**: DevOps, IT Operations

## Media

Upload in this order, from `splunkbase/screenshots/`. All are 1200 by 900, taken on Splunk
Enterprise 10.4.3 against 20,000 compact events from the OpenTelemetry demo.

| File | Caption |
|---|---|
| `1_before_after.png` | One log line: 354 bytes stored in Splunk, and the original 1,065-byte line users search and see |
| `2_search_bar.png` | The search bar with `tenxsearch`: 438 matching events, expanded to their original lines |
| `3_dashboard.png` | A user's own classic dashboard in plain SPL: counts and events come back expanded with no changes to the panels |
| `4_analytics.png` | Analytics: compact events, templates, compression ratio and storage saved |
| `5_compile_alert.png` | Compile Alert: a search saved once as a scheduled alert, which Splunk runs as a normal saved search |

Repository name: `log-10x/splunk-app`. Repository URL: https://github.com/log-10x/splunk-app

## Contact

| Field | Value |
|---|---|
| Developer support | I will support my app: support@log10x.com |
| Contact notes | Issues and feature requests: https://github.com/log-10x/splunk-app/issues |

## Release information

| Field | Value |
|---|---|
| Version | 1.1.2, read from the package |
| Splunk platform compatibility | Splunk Enterprise 9.4, 10.0, 10.2, 10.4 |
| CIM | None |

These are every Splunk Enterprise line Splunk supports today, and each is tested: 9.4.15,
10.0.10, 10.2.7 and 10.4.3, each a fresh install of this package. Splunk ships on-premises
releases every other minor, so 10.1 and 10.3 exist only on Splunk Cloud Platform, where
compatibility is set by cloud vetting after upload rather than selected here. Splunkbase
requires a release to run on every version it names.

**Release notes**

> First Splunkbase release.
>
> - Search compact events from the search bar, saved searches, alerts and the REST API with
>   the `tenxsearch` command; classic dashboards keep their SPL.
> - NOT, OR, groups, phrases, inline `earliest=`, field conditions, and values such as IP
>   addresses and hostnames match as on the original data.
> - A search that cannot be rewritten is refused with a message.
> - The Compile Alert view compiles an alert once into a native saved search.
> - The Analytics and Diagnostics dashboards find compact events through the `tenx-events`
>   macro.
> - Tested on Splunk Enterprise 9.4, 10.0, 10.2 and 10.4. The package passes AppInspect's
>   Splunk Cloud checks.
>
> After upgrading, restart Splunk so Splunk Web serves the updated dashboard script.

## Checks run on this package

| Check | Result |
|---|---|
| AppInspect 4.3.1: default, cloud, future, private_victoria, private_classic | 0 errors, 0 failures, 0 future failures |
| Splunkbase file standards: one root folder, no hidden or compiled files, no `local/` | met |
| 30 checks per version on a fresh install of this package: search matrix, saved search, refusal, both dashboards, the hook, the search bar, navigation | 30 of 30 on 9.4.15, 10.0.10, 10.2.7 and 10.4.3 |
| Unit tests, Python 3.9 and 3.13 | pass |

Warnings AppInspect reports, none blocking: SplunkJS telemetry notice, Python 2/3 notice,
`collections.conf` present, `check_for_updates` set for a published app, Splunk SDK 2.1.1.
The SDK is pinned to 2.x because 3.x does not run on Splunk 9.4.

## Build the package

From the repository root:

```sh
rm -rf /tmp/sbpkg && mkdir -p /tmp/sbpkg
rsync -a --exclude 'local/' --exclude '__pycache__/' --exclude '*.pyc' --exclude '*.pyo' --exclude '.*' \
  tenx-for-splunk/ /tmp/sbpkg/tenx-for-splunk/
cd /tmp/sbpkg && COPYFILE_DISABLE=1 tar --format ustar -czf tenx-for-splunk-1.1.2.tar.gz tenx-for-splunk
```

## Submitting

1. Log in to Splunkbase with the company account that will own the listing, select
   **Submit an app**, and accept the Splunk Developer Agreement.
2. Fill in each section from this file, upload the package, and wait for AppInspect.
3. Add editors from the Editors page.
4. Publish.

Splunk permits press releases about a Splunkbase app only for formal Splunk partners.
