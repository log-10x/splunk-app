# Save-time alert compilation

A scheduled alert runs on the server, where the dashboard hook never fires. The app
compiles the alert's search once, when it is saved, into native SPL, and stores that. The
scheduler then runs an ordinary saved search with no Python between it and the data.

`| tenxsearch` also works in a saved search, but every run then proxies a nested job and
writes each event out through Python. Compiling avoids that cost.

## Compiling an alert

Open **Compile Alert** in the app's navigation, enter the search and the alert settings,
and select **Compile**. The view shows the compiled search, its strategy, and any reason
to review it. A clean result is saved at once. A result flagged for review is saved only
after **Confirm and schedule**.

**Recompile all managed alerts** recompiles every alert the view created, from the search
as originally written. Run it after new templates arrive, so their hashes join the
prefilter. It also converts an existing `| tenxsearch searchstring="..."` alert into a
compiled one. It applies only clean results whose compiled form changed.

The same actions are available at the `/tenx-alert` REST endpoint:

| Request | Result |
|---|---|
| `POST search=... name=... <alert attributes>` | Compiles and saves the alert |
| the same with `confirm=true` | Saves a result flagged for review |
| `POST action=recompile` | Recompiles every managed alert |

The search as written is stored on the saved search as `tenx_original_search`.

## Strategies

| Strategy | When | Stored | HTTP |
|---|---|---|---|
| NATIVE | The search selects a compact sourcetype or source | The compiled search | 200 |
| PASSTHROUGH | The search does not touch compact data | The search unchanged | 200 |
| RETRYABLE | The template lookup failed | Nothing; the existing alert is kept | 503 |
| REJECTED | The search cannot be parsed or compiled | Nothing | 422 |

## The compiled form

`index=main sourcetype=tenx_encoded payment declined` compiles to:

```spl
search index=main sourcetype=tenx_encoded ("payment" OR ("~h_pay" OR "~h_pay2")) AND ("declined" OR ("~h_pay2"))
| `tenx-inflate` | extract | spath | fields - tenx_hash, tenx_var_0, tenx_vars
| search payment declined
```

Each word matches either as a variable value in the compact event or through the hashes of
the templates whose text carries it. After expansion, the original terms run again, so the
alert returns exactly the events the search returns on the original lines. The rules are
the same as for interactive search; see `tenx_search_builder.py`.

A field condition is applied after expansion, with a key=value extraction on the expanded
text:

```spl
... | `tenx-inflate` | extract | spath | fields - ... | extract kvdelim="=" pairdelim=" " | search level=error | search payment
```

`NOT` is applied after expansion as well: `payment NOT declined` prefilters on `payment`
alone and then excludes `declined` from the expanded events.

## Results flagged for review

A NATIVE result is flagged, and saved only on confirmation, when one of these holds. The
compiled search returns the same events; the flag names its cost or dependency:

| Flag | Why |
|---|---|
| The search uses `NOT` | The exclusion does not narrow the prefilter, so the search scans wider |
| No keyword terms, such as `status=500` alone | No prefilter; every run scans the whole compact sourcetype |
| Every keyword is negated or its lookup was cut short | The same full scan |
| A keyword's lookup ran out of time or matched more templates than can be fetched | That keyword is left out of the prefilter |
| No template matches a keyword | The alert fires only when the word appears as a variable value |
| A field condition | It depends on the expanded text carrying space-separated `key=value` pairs |

A PASSTHROUGH result is flagged when the search still names a configured compact
sourcetype or source, by name or by a matching wildcard such as `sourcetype=tenx_*`.
Detection reads the sourcetype and source named in the search. A search that selects
compact data by eventtype, index alone or macro compiles as PASSTHROUGH without a flag.

## Time

The alert's time range selects on `_time`, which for a compact event is the time Splunk
indexed it. See [Event time on compact events](README.md#event-time-on-compact-events).

## Permissions

`/tenx-alert` requires authentication and makes every Splunk call with the caller's own
session. Alert attributes in the request are passed through to `saved/searches`, so
Splunk accepts only the attributes the caller's role may already set, and the stored
search runs as its owner. The endpoint grants no privilege the caller lacks. Template
hashes are quoted and escaped before they enter the compiled search.

## Tests

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r tests/requirements-test.txt
pytest tests/
```

`tests/support/local_search_manager.py` stands in for Splunk's parser and the template
lookup, so the compiler runs end to end against a local template store without a Splunk
instance.
