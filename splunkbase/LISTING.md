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

> With the Log10x App, Splunk can index compact log events and still search, chart and alert on the original lines. The 10x Receiver stores each event as a template hash plus the values that change, so a stream of repeated patterns takes less of the license. On the OpenTelemetry demo, Splunk's license meter counted 63.91% fewer bytes, encoded events and templates included, and every line expanded back byte-identical with the Receiver settings in the installation steps (measurement: https://github.com/log-10x/benchmarks/tree/main/splunk-license). The same license then holds more: sources that were sampled, filtered or kept out of Splunk to stay under the limit can come back, or the license can be smaller.
>
> To search by what the lines say, write the tx macro in front of an ordinary search: index=my_index `tx` "payment failed" NOT retry. It runs as native SPL in the search bar, Dashboard Studio, saved searches and alerts, and NOT, OR, groups, phrases, field conditions, and values such as IP addresses and hostnames behave as they do on the original data. Classic dashboards keep their SPL: the browser sends each panel's search to the app, which rewrites it on the server. An alert created in the app's Compile Alert view is compiled once into a native saved search.
>
> The 10x Receiver produces compact events, and it is free on up to 10 nodes (https://www.log10x.com/pricing). No sign-up is required: with no license token it runs the full product on up to 10 nodes, air-gapped, with no expiry (https://doc.log10x.com/manage/license/). The app itself is open source under the MIT license.

**Short description**

> Send Splunk the logs that sampling and filters keep out to fit the license, on that same
> license. Compact events take a fraction of the volume and expand back byte-identical at
> search time; classic dashboards keep their SPL, and one macro in front of a search covers the
> search bar, Dashboard Studio, saved searches and alerts.

**Details**

> **Two ways to search compact events**
>
> - Classic dashboards: `dashboard.js` routes each panel's search through the app's REST
>   endpoint, which rewrites it. Panels keep their SPL. Copy the file into another app's
>   `appserver/static/` to cover that app's dashboards.
> - Everywhere else: write the `tx` macro in front of the search terms, after the index and any
>   time terms, as in ``index=my_index earliest=-4h `tx` "payment failed" NOT retry``. The words
>   after `tx` are the search, written as it would be on the original data.
>
> **Dashboards**
>
> Analytics shows compact event counts, active templates, compression ratio and storage
> saved. Diagnostics checks each stage from template arrival to expansion. Both find compact
> events through the `tenx-events` macro.
>
> **Search coverage**
>
> - Outside a classic dashboard, a keyword search without `tx` returns only the events where
>   the word is a value, and a search with no keywords returns compact `~hash,...` rows.
> - `tx` stops a search with a message when `earliest=` or `latest=` comes after it, or when a
>   comma after it is outside quotes: Splunk would match the first against no event and the
>   second literally.
> - Classic dashboards and the `| tx` command rewrite the search, and refuse two shapes with a
>   message: a sourcetype inside an OR with other terms, `sourcetype=x OR host=y`, and a quoted
>   phrase that contains an escaped quote.
> - Dashboard Studio loads no app JavaScript; its panels use the `tx` macro, which passes
>   Splunk's risky-command check.
> - A compact event's `_time` is the time in its original line where the template has a
>   timestamp, and its index time where it has none. The setting applies where events are
>   parsed, so the app is installed on indexers or heavy forwarders as well as search heads.
>
> **Speed**, on one laptop running Splunk 10.4.3: a `tx` search over 157,228 compact events
> returns in about 1.5 to 4 seconds, where the same search over the raw lines takes under a
> second; the `| tx` command, which writes every event out itself, takes two to five times as
> long. A classic dashboard expands 20,000 events in about 5 seconds.
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
> - **A search returns zero events.** Write `tx` in front of the search terms, with `earliest=`
>   and `latest=` before it, or run it from a classic dashboard in an app that carries
>   `dashboard.js`.
> - **A `tx` search stops with a message.** Move `earliest=` and `latest=` before `tx`; remove
>   a comma after it or put the text in quotes.
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
| `5_compile_alert.png` | Compile Alert: alert on the original log text; Splunk runs it on its schedule, and new log statements join it automatically |

Repository name: `log-10x/splunk-app`. Repository URL: https://github.com/log-10x/splunk-app

## Contact

| Field | Value |
|---|---|
| Developer support | I will support my app: support@log10x.com |
| Contact notes | Issues and feature requests: https://github.com/log-10x/splunk-app/issues |

## Release information

| Field | Value |
|---|---|
| Version | 1.1.7, read from the package |
| Splunk platform compatibility | Splunk Enterprise 9.4, 10.0, 10.2, 10.4, 10.6 |
| CIM | None |

Each line is tested: 9.4.15, 10.0.10, 10.2.7 and 10.4.3, each a fresh install of 1.1.2. 1.1.3
changed one `props.conf` key, checked on 10.4.3 and measured on 9.4. 1.1.4 changes how
templates are stored; it is checked on 9.4.15, 10.4.3 and 10.6.0.5, on a fresh install and an
upgrade over 1.1.3. 1.1.5 changes the compact sourcetype's event time and the expansion macro; it is
checked on 9.4.15, 10.4.3 and 10.6.0.5, each a fresh install. 1.1.6 adds the `tx` macro and
its command and replicates the template collection; it is checked on 10.4.3 as an upgrade over
1.1.5, and on 9.4.15 and 10.6.0.5 as a fresh install. 1.1.7 changes how fields and dates come out of an expanded event; it is checked on 10.4.3 as an upgrade over 1.1.6, and on 9.4.15 and 10.6.0.5 as a fresh install. Splunk
ships on-premises releases every other minor, so 10.1 and 10.3 exist only on Splunk Cloud
Platform, where compatibility is set by cloud vetting after upload rather than selected here.
Splunkbase requires a release to run on every version it names.

**Release notes**

Paste the block for the version being uploaded. Splunkbase keeps notes per release.

1.1.7:

> - Field conditions after `tx` match key=value text, such as `status=600`, syslog's `uid=0` or `EventCode=4624`: the fields of an expanded event are the ones Splunk extracts from the original line, key=value pairs and JSON alike, and no others.
> - Dates expand as written when a day, hour, minute or second has no leading zero, such as syslog's `Sep  5 00:14:52`.
> - A timestamp that was already an epoch number expands as that number.
> - A `tx` search with nothing to narrow on no longer highlights the whole of every event.
> - After upgrading, run `index=tenx_dml sourcetype=tenx_dml_raw_json earliest=0 | sendalert tenx_dml_to_kv` once, so that templates stored by an earlier version take the date changes.

1.1.6:

> - Search compact events by writing the `tx` macro in front of an ordinary search: ``index=app_logs `tx` "payment failed" NOT retry status=500``. It runs as native SPL in the search bar, Dashboard Studio panels, saved searches and alerts, and passes Splunk's risky-command check. The words after it behave as on the original lines; `earliest=` and `latest=` go before it, and a time modifier or an unquoted comma after it stops the search with a message. The `tx` and `tenxsearch` commands keep working for saved searches written with them.
> - The template collection is replicated to the indexers with the knowledge bundle, so expansion runs on the indexers instead of the search head.
> - Template records are read at search time instead of being stored in the index files a second time.
> - The `tx`, `tenx-events` and `tenx-templates` macros are shared with every app.

1.1.5:

> - A compact event's `_time` is now the time in its original log line wherever the template has a timestamp, so searches and alerts over a time range select late and replayed logs by their own time. Events from templates without a timestamp keep their index time. The setting adds no licence-metered bytes. It applies where events are parsed: install the app on the indexers or heavy forwarders as well as on the search heads.
> - Expanded timestamps render in UTC for every viewer at every hour of the year. Around a daylight-saving transition they could render an hour off for a viewer in a zone that observes one, and a zone in the timestamp format printed the viewer's offset; it now prints `+0000` or `UTC`.

1.1.4:

> - The app's searchable copy of each template is now written with Splunk's `collect` as sourcetype `stash`, which Splunk does not count against the licence. Template records sent by the Receiver are counted as before.
> - Two different templates under one template hash are detected when stored. Their events stay compact and carry `tenx_expand_refused=hash-conflict` instead of expanding with the wrong text, and the Diagnostics dashboard lists them.
> - A stored template that is a cut-short copy of the one the Receiver sends is replaced by the whole template.
> - A compact event from a template with no values now expands.
> - The new `tx` command takes the search as written, with no `searchstring=` option and no
>   escaped quotes: `| tx index=app_logs sourcetype=tenx_encoded "payment failed" NOT retry`. `tenxsearch` works as
>   before.
> - Recompile all managed alerts keeps the rest of an alert's pipeline, such as
>   `| stats count`, when it converts a `tenxsearch` alert, and converts `tx` alerts too.

1.1.3:

> Compact events up to 256 KB now expand whole. In 1.1.2, events over Splunk's 10,000-byte default were cut when they arrived through a forwarder, a file input or the HEC raw endpoint; the HEC event endpoint was not affected.

1.1.2:

> First Splunkbase release.
>
> - Search compact events from the search bar, saved searches, alerts and the REST API with
>   the `tenxsearch` command; classic dashboards keep their SPL.
> - NOT, OR, groups, phrases, inline `earliest=`, field conditions, and values such as IP
>   addresses, hostnames, dates and times match as on the original data.
> - A search that cannot be rewritten is refused with a message.
> - The Compile Alert view compiles an alert once into a native saved search, and a scheduled
>   pass keeps compiled alerts current as new log statements appear.
> - The Analytics and Diagnostics dashboards find compact events through the `tenx-events`
>   macro.
> - Tested on Splunk Enterprise 9.4, 10.0, 10.2 and 10.4.

## Checks run on this package

| Check | Result |
|---|---|
| 1.1.7 unit tests | 397 passed, among them each of the 1.1.7 changes: the field extraction and the highlight in `tx`, unpadded date letters, epoch timestamps, and refreshing a stored template whose derived fields changed |
| 1.1.7 as packaged on Splunk 10.4.3, upgraded in place over 1.1.6; nine log shapes (Apache, Proxifier, Kubernetes JSON, Java with stack traces, key=value application logs, BSD syslog, CSV, Windows event text, and lines with `$`, `/`, `~`, quotes, Unicode, tabs, leading zeros, UUIDs and 8 KB values), each encoded by edge-10x 1.1.142 and indexed raw beside its compact form | every line expands back as it was; the fields of every single-line event equal Splunk's own on the raw line (21,804 events); 25 of 25 key=value field searches and 155 of 162 word, value, phrase, OR, NOT and wildcard searches return the raw lines exactly, the other 7 differing only where lines are grouped into one event or a number sits inside a timestamp; one run of the template load after the upgrade rewrites the records stored by 1.1.6 |
| 1.1.7 as packaged, fresh install on Splunk 9.4.15 and on 10.6.0.5; eight of the same log shapes | every line expands back as it was; fields equal Splunk's on 10,825 events; 11 of 11 field searches as raw; `status=600` on key=value text found; no search highlights every event; the risky-command check, the Search app, both stops, an unpadded syslog day and an epoch timestamp as on 10.4.3 |
| 1.1.7 AppInspect 4.3.1: default, cloud, future, private_victoria, private_classic | 0 errors, 0 failures |
| 1.1.6 unit tests | 386 passed, among them the parser of the words after `tx`: Splunk's precedence, `IN`, `TERM()`, `CASE()`, escaped quotes, and the cases that select every event in range |
| 1.1.6 as packaged, upgraded in place over 1.1.5's configuration on Splunk 10.4.3; the OpenTelemetry demo sample, 20,120 compact events, truth from the same lines indexed raw | 41 searches typed as `` `tx` <search> ``: 31 return the raw lines exactly, 8 differ only where lines are grouped into one event (a stack trace is one event), and an unquoted comma stops with its message; a time window after `tx` stops with its message and before it returns the window's 60 events of 60 |
| 1.1.6 `tx` contexts on Splunk 10.4.3 | passes Splunk's risky-command check (the one Dashboard Studio and search links apply); runs from the Search app; inside `append` and wrapped in another macro it expands every event in range with a warning and returns the same counts; a role with only the `search` capability, a scheduled search, and searches of 1, 10, 60 and 200 KB return the same counts |
| 1.1.6 as packaged, fresh install on Splunk 9.4.15 and on 10.6.0.5; the same 20,000 compact events and their 2,988 templates | the app loads as 1.1.6; `tx` returns 1,974, 688 and 468 for a word, a phrase and an OR, as on 10.4.3, with each event expanded to its original line; passes the risky-command check and runs from the Search app; a comma or a time modifier after `tx` stops with its message (9.4 shows it as an error with no events, 10.6 fails the search) |
| 1.1.6 AppInspect 4.3.1: default, cloud, future, private_victoria, private_classic | 0 errors, 0 failures |
| AppInspect 4.3.1: default, cloud, future, private_victoria, private_classic | 0 errors, 0 failures, 0 future failures |
| Splunkbase file standards: one root folder, no hidden or compiled files, no `local/` | met |
| 46 checks per version on a fresh install of 1.1.2: search matrix, saved search, refusal, both dashboards, the hook, the search bar, navigation, scheduled recompile | 46 of 46 on 9.4.15, 10.0.10, 10.2.7 and 10.4.3 |
| Long compact events on Splunk 10.4.3, 1.1.3 upgraded in place over 1.1.2: the OpenTelemetry demo sample, 3,723 compact events, 11 over 10,000 bytes, the longest 25,472, sent through the HEC event endpoint, the HEC raw endpoint and a file input | every event stored whole; 5,000 of 5,000 lines expand byte-identical on each path (1.1.2 on the raw endpoint and file input: 11 events cut at 10,000 bytes, 4,710 lines back) |
| 1.1.4 on Splunk 10.4.3, the E21 template set (2,991 templates) and 20,000 compact events: searchable copy written with `collect` as `stash` | 2,991 of 2,991 copies byte-identical to the 1.1.3 copy, one template per event, the longest 43,004 characters whole; `license_usage.log` shows 0 bytes for them while a control written the same way with an ordinary sourcetype is metered |
| 1.1.4 search through the new copy, fresh install and upgrade over 1.1.3 copies | the same template hashes for 10 of 10 terms; `tenxsearch` equals the expanded truth on 6 of 6 searches (error 438, cartstore 1,974, accounting 75, "connection refused" 217, kafka 3,728, NOT bootstrap 19,992) |
| 1.1.4 hash conflict: a second, different template sent under a hash 3,916 events use | key marked `hash-conflict`, all 3,916 events left compact with `tenx_expand_refused`, the other 16,084 expand; the same template sent again marks nothing (0 of 2,991) |
| 1.1.4 on Splunk 9.4.15: 1.1.3 from Splunkbase (sha256 fe0e2ba2...) installed and filled, then upgraded in place to 1.1.4 | re-sending all 2,991 templates marks none; the same template hashes for 6 of 6 terms; `tenxsearch` equals the expanded truth on 3 of 3 (error 438, cartstore 1,974, NOT bootstrap 19,992) |
| 1.1.4 on Splunk 9.4.15, fresh install | 2,991 of 2,991 copies written as `stash`, byte-identical to the 1.1.3 copy, one template per event, longest 43,004 characters; 0 bytes metered for them while a control with an ordinary sourcetype is metered; a conflicting template leaves its 3,916 events compact with `hash-conflict` |
| 1.1.4 on Splunk 10.4.3 through the Receiver, 20,000 Kubernetes records of the OpenTelemetry demo, Fluent Bit and Fluentd configured as in the setup guide | every compact event carries the Kubernetes metadata as indexed fields; with Fluentd, 2,581 templates for 2,581 event hashes; all 12,868 compact events expand, 19,974 of 20,000 lines byte-identical, the other 26 being empty messages the Receiver does not return; licence meter 1,427,624 bytes against 3,479,139 for the same records sent message-as-event with the metadata as fields |
| 1.1.4 `tx` on Splunk 10.4.3, the same 20,000 events | equals the expanded truth on 17 of 17 searches, among them a quoted phrase with `NOT` and a parenthesised group, quoted field values, a subsearch and a time modifier, and equals `tenxsearch` on the 9 run through both; a phrase containing an escaped quote is refused by both commands; `\| tx` with no search fails with a message |
| 1.1.4 Recompile all managed alerts on Splunk 10.4.3: one alert saved as `\| tx ... \| stats count`, one as `\| tenxsearch ... \| stats count` | both converted to native SPL that ends in `\| stats count`, each returning 217, the expanded truth |
| 1.1.4 on Splunk 10.6.0.5, fresh install: the E21 template set and 20,000 compact events through the HEC event endpoint, truth from the same events decoded by the engine | 2,991 of 2,991 copies written as `stash`, one template per event, longest 43,004 characters; 0 bytes metered for them while a control written the same way with an ordinary sourcetype is metered (445,251 bytes); `tx`, `tenxsearch` and the truth agree on 12 of 12 searches, among them a phrase with `NOT`, a parenthesised group, a field value, a time modifier and a subsearch; `\| tx` with no search and an escaped quote are refused with a message; a conflicting template leaves its 3,916 events compact with `hash-conflict`, the other 16,084 expand; `tests/live_endpoints.py` 3 of 3; Recompile all managed alerts converts a `\| tx` and a `\| tenxsearch` alert to native SPL ending in `\| stats count`, each returning 217, the truth |
| 1.1.5 event time on Splunk 9.4.15, 10.4.3 and 10.6.0.5, each a fresh install: the OpenTelemetry demo sample, 157,228 compact events from engine 1.1.139, truth from Splunk's own timestamp extraction on the same lines indexed raw | the same on each version: of the 134,668 events whose original line carries a timestamp Splunk recognizes, 134,340 get that time as `_time` to the second and 133,658 to the millisecond (1.1.4: 0); the other 328 are lines without a full date (glog carries no year, three lines only a time of day) and three lines where Splunk reads a number as a time; events without a timestamp keep their index time; no field added to the index |
| 1.1.5 licence meter on Splunk 10.4.3: the E21 run (log-10x/benchmarks `splunk-license/`), the OpenTelemetry demo sample through a Universal Forwarder, engine 1.1.139 | compact events metered 74,338,244 bytes, exactly their raw text, with the event time set; licence-metered reduction 63.91% |
| 1.1.5 timestamp rendering on Splunk 9.4.15, 10.4.3 and 10.6.0.5: 10,708 events at 2,677 instants, every ten minutes for 14 hours either side of the 2026 daylight-saving transitions plus every six hours through 2026, four timestamp formats, viewers in UTC, America/New_York, Europe/London, Australia/Sydney, Pacific/Chatham, America/Adak, Asia/Kolkata and Etc/GMT-4 | every line the UTC text in every zone on each version (1.1.4, the same on each: an hour off at 54 instants for New York, 126 for Sydney, 160 for Chatham, 114 for Adak and 6 for London, and the viewer's offset printed for a zone in the format) |
| 1.1.4 on Splunk 10.6.0.5: 1.1.3 from Splunkbase (sha256 fe0e2ba2...) installed and filled, then upgraded in place to 1.1.4 | re-sending all 2,991 templates marks none; 6 of 6 terms give the same count through `tenxsearch` on 1.1.3 and through `tx` and `tenxsearch` on 1.1.4, equal to the truth |
| 1.1.4 as packaged, with the `tx` examples naming the compact sourcetype, on Splunk 10.6.0.5, fresh install | the search assistant shows `\| tx index=app_logs sourcetype=tenx_encoded "connection refused" NOT retry`, and `\| tx` with no search names the same form; 2,991 templates in the KV, 2,991 `stash` copies; `tx`, `tenxsearch` and the truth agree on 6 of 6 searches; AppInspect 4.3.1: 0 failures and 0 errors on the default, cloud, future, private_app, private_classic and private_victoria tag sets, the same results as the package before the change |
| Unit tests, Python 3.9 and 3.13 | 327 pass |

Warnings AppInspect reports, none blocking: SplunkJS telemetry notice, Python 2/3 notice,
`collections.conf` present, `check_for_updates` set for a published app, Splunk SDK 2.1.1.
The SDK is pinned to 2.x because 3.x does not run on Splunk 9.4.

## Build the package

From the repository root:

```sh
rm -rf /tmp/sbpkg && mkdir -p /tmp/sbpkg
rsync -a --exclude 'local/' --exclude '__pycache__/' --exclude '*.pyc' --exclude '*.pyo' --exclude '.*' \
  tenx-for-splunk/ /tmp/sbpkg/tenx-for-splunk/
cd /tmp/sbpkg && COPYFILE_DISABLE=1 tar --format ustar -czf tenx-for-splunk-1.1.7.tar.gz tenx-for-splunk
```

## Submitting

1. Log in to Splunkbase with the company account that will own the listing, select
   **Submit an app**, and accept the Splunk Developer Agreement.
2. Fill in each section from this file, upload the package, and wait for AppInspect.
3. Add editors from the Editors page.
4. Publish.

Splunk permits press releases about a Splunkbase app only for formal Splunk partners.
