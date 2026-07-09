# Save-time alert compilation for 10x-compact data

Status: **prototype** — the compiler and its tests are built and green. Wiring it into the
saved-search save/update flow (a REST handler + a UI control + a bulk-migrate pass) and
verifying on a live Splunk instance are the next steps, described at the end.

## Why this exists

The interactive path makes compact (encoded) events searchable transparently: a browser
hook (`appserver/static/javascript/search/tenx_search_hook.js`) intercepts the search the
dashboard POSTs to `/search/jobs`, points it at `/tenx-search`, and the REST handler
rewrites the SPL (hash prefilter + `` `tenx-inflate` ``) before the job runs.

An **alert is a saved search the scheduler runs server-side**. No browser is involved, so
that hook never fires. The only pre-existing fallback is typing the `| tenxsearch` generating
command into every alert, which proxies a nested job and re-streams every event through
Python — slow, and not transparent.

Two Splunk-internals findings (validated externally; see the handoff and consult transcript
under `dotcom/blog/review-agendas/`) frame the fix:

1. **There is no supported pre-dispatch SPL rewrite hook for the scheduler.** Ruled out:
   browser JS, Splunk-Web proxy, auto-applied macros, overriding core `search` via
   `commands.conf`, `alert_actions.conf`, `SEDCMD`/`INGEST_EVAL`, report/datamodel
   acceleration, `savedsearches.conf` defaults, `authorize.conf` `srchFilter`, and all
   search-time knowledge objects.
2. **Automatic search-time config can deliver decoded _fields_ but never keyword-searchable
   `_raw`.** Base keyword matching runs against indexed encoded terms; `EVAL-_raw` is
   version-dependent/undocumented; `EVAL-*` runs before `LOOKUP-*`, so a calculated `_raw`
   cannot use looked-up template parts.

So the fix is not a hidden hook. It is: **compile the search once, at save time, into native
SPL, and store that.** The scheduler then runs an ordinary, supported saved search — no proxy
job, no per-run Python tax. Existing alerts are migrated the same way.

## The save / REST surface (map)

There is no server-side "before a saved search is written" hook in Splunk (this is the same
class of gap as the no-pre-dispatch finding). Saved searches are created/updated through:

- **REST** — `POST /servicesNS/{owner}/{app}/saved/searches` (create) and
  `POST .../saved/searches/{name}` (update), with `search`, `alert_type`, `cron_schedule`,
  `actions`, `dispatch.*`, etc. This is also what the SDK and the deployer use.
- **UI** — the "Save As → Alert" dialog in Search & Reporting, and
  *Settings → Searches, reports, and alerts*.

Neither offers a transparent interception point. So compilation has to be an **explicit
action**, mirroring the app's existing seams:

| Existing seam | Mechanism | Precedent for |
|---|---|---|
| `/tenx-search` | persistent REST handler (`restmap.conf` `[script:tenx-search]`, `web.conf` `[expose:tenx-search]`) | the alert-compile handler |
| `/tenx-config` | persistent REST handler + React setup page (`appserver/static/.../views/tenx_setup_page.js`) | the UI control that calls it |

**Confirmed seam:** a new persistent REST handler (working name `/tenx-alert`) that accepts a
human search, compiles it with `TenxAlertCompiler`, and writes the compiled SPL into
`saved/searches` (storing the human original in a stanza attribute so the alert can be
recompiled when new templates arrive) — plus a small UI control and a bulk-migrate call over
existing alerts. This is a sibling of `/tenx-search` and `/tenx-config`, not a new pattern.

## What is built now: the compiler

`bin/tenx_alert_compiler.py` — `TenxAlertCompiler.compile(user_search) -> AlertCompileResult`.

It reuses the proven resolution logic via a new **`TenxSearchBuilder.build(base_search)`**
method (a behavior-preserving refactor: `resolve()` now delegates to `build()` and keeps its
exact external contract; `build()` additionally returns the `ResolvedState` so a caller can
decide policy). The compiler itself holds **no Splunk connection** — all Splunk coupling lives
in the injected builder's `search_manager`. That makes `compile()` a pure function of
(search, injected dependencies), so it is unit-tested end to end against a local template
store with no live instance.

`compile()` classifies each search into one strategy:

| Strategy | When | Stored SPL |
|---|---|---|
| **NATIVE** | search touches compact data | `search <mods> ((words) OR (tenx_hash IN (…))) \| \`tenx-inflate\` \| extract [\| where …] [\| search …] [\| …rest]` |
| **PASSTHROUGH** | search does not touch compact data | the original, unchanged |
| **ESCAPE_HATCH** | too complex to compile statically (`ResolvedState.COMPLEX`) | `\| tenxsearch searchstring="<original>"` — correct but slower; `needs_review=True` |
| **RETRYABLE** | transient DML lookup failure at compile time | nothing — keep the existing alert, retry later |
| **REJECTED** | unparseable, or cannot be compiled safely (e.g. `NOT` on compact data) | nothing (surface the reason) |

Each result also carries `needs_review` (a human should confirm before it is applied) and a
`reason`. The compiler decides NATIVE vs PASSTHROUGH off a structured `engaged` flag from
`build()` — not by scanning the output text for the inflate macro — so a user who types
`` `tenx-inflate` `` into their own search can't fool the classification.

**ESCAPE_HATCH is currently a defensive path.** The real builder does not emit
`ResolvedState.COMPLEX` for the ambiguous searches you'd expect (see the measured table
below); it passes them through as SUCCESS, and the safety net flags them as
PASSTHROUGH + `needs_review`. ESCAPE_HATCH fires only if `build()` ever returns COMPLEX.

Notes on the NATIVE form:
- The stored search is **hash-prefiltered** (`tenx_hash IN (…)`), which is the cheap, precise
  path the handoff calls for — a hash *is* a message type. The `(words)` clause additionally
  catches matches in the variable portion of encoded events, and the trailing `| search
  <terms>` re-narrows to true matches, so both template-text and variable-value matches are
  covered.
- Output is normalized to the idiomatic saved-search form (leading `search`, not `| search` —
  the builder joins commands with a leading pipe).
- Time windows come from the alert's `dispatch.earliest/latest` against indexed `_time`; the
  inflate macro rewrites `_raw` but not `_time`, so **`_time` must be correct at ingest/HEC**
  (a settled constraint, not this compiler's job).

## Empirical behavior (measured, not assumed)

Representative inputs → strategy (config: `tenx_encoded` is a compact sourcetype). These are
measured against the real builder + a local template store, and pinned by tests.

| Input | Strategy |
|---|---|
| `index=main sourcetype=tenx_encoded payment failed` | NATIVE (prefilter over payment templates) |
| `sourcetype=tenx_encoded status=500 payment` | NATIVE (`\| where status=500`) |
| `sourcetype=tenx_encoded payment \| stats count` | NATIVE (inflate before `stats`) |
| `sourcetype=tenx_encoded` (no terms) | NATIVE (inflate all, no prefilter) |
| `sourcetype=tenx_encoded level=error` | NATIVE + **needs_review** (string field value, see below) |
| `index=main error` / `error` | PASSTHROUGH |
| `index=main error NOT healthcheck` | PASSTHROUGH (NOT is fine off compact data) |
| `sourcetype=tenx_encoded error OR sourcetype=other` | PASSTHROUGH + **needs_review** |
| `sourcetype=tenx_* payment` | PASSTHROUGH + **needs_review** (wildcard, glob-matched) |
| `sourcetype=tenx_encoded NOT payment` | **REJECTED** (negation, see below) |
| transient DML lookup failure at compile time | **RETRYABLE** |
| empty / unparseable | REJECTED |

### Builder blind spots the compiler defends against

An adversarial review found several places where the reused builder (and its parser) produce
output that is wrong or a silent passthrough. The root fixes belong in the shared builder and
must be verified on live Splunk (part of the wiring phase); until then the compiler refuses to
**certify** these as clean:

- **`NOT` is silently dropped.** `TenxSearchAstNodeFactory` prunes negation nodes, so the
  builder compiles `sourcetype=tenx_encoded NOT payment` into the *positive* search — an
  inverted alert. The compiler detects the `NOT` operator (quote-aware) on a compact search
  and **REJECTs** it rather than store a semantically-inverted alert. Root fix: stop pruning
  `not_logical_expression` so `SpecifierFinder`'s negation handling is live again.
- **String-valued field conditions compile to a dead `\| where`.** `where_fields()` emits
  `\| where level=error`, where the unquoted `error` is read by `where` as a *field
  reference*, so the clause matches nothing. Numeric literals (`status=500`) are the one RHS
  shape that works. The compiler flags any string-valued field condition as **needs_review**.
  Root fix: quote non-numeric values, or translate `field=value` equality to a post-inflate
  `\| search field=value` (search-command semantics, which is what the user wrote).

### Passthrough safety net (heuristic)

The builder **silently passes a search through** (SUCCESS, not engaged) when it cannot
*confidently* prove the search targets compact data — mixed `sourcetype=a OR sourcetype=b`, a
wildcard `sourcetype=tenx_*`, or a shape its grammar can't fully parse. For an alert that is
dangerous: it would count un-inflated encoded events. The compiler's safety net
(`_referenced_tenx_sources`) extracts the `sourcetype=`/`source=` values a search selects on
and flags the passthrough as `needs_review` when any configured compact name matches — exactly
(`sourcetype=tenx_encoded`) or by glob (`sourcetype=tenx_*` matches `tenx_encoded` via
`fnmatch`). It over-flags rather than under-flags.

This net is a heuristic, not a proof. Compact data can still reach an alert un-flagged when it
is selected without a literal `sourcetype=`/`source=` term — via `eventtype`, an index-only
search, or a sourcetype hidden behind a macro. Cover those on live Splunk; do not treat the
net as a guarantee.

## Running the tests

The app bundles `parsimonious` and `splunklib` for Splunk's Python 3.7; those vendored copies
do not import under a modern interpreter. The tests therefore use a modern `parsimonious`
(pinned in `tests/requirements-test.txt`) and a tiny offline `splunklib` stub installed by
`tests/conftest.py` (nothing in the tested code paths calls into Splunk — a local
search-manager double is injected).

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r tests/requirements-test.txt
pytest tests/
```

The doubles (`tests/support/local_search_manager.py`) reproduce the two Splunk round-trips
the builder makes — SPL command splitting and the `tenx_dml_pure` hash lookup — locally, so
`compile()` is exercised against the real demo template CSV (`demo/tenx_templates_demo.csv`).
They approximate Splunk (single-element `args.search`, no subsearch splitting, substring
keyword matching); the compiled-SPL semantics they cannot prove must be checked live.

## Not built yet — the wiring plan

1. **`/tenx-alert` REST handler** (persistent, sibling of `tenx_search_handler.py`): `POST`
   with a human `search` + alert attributes → compile → dispatch on strategy: on `storable`,
   write the compiled SPL plus the human original to `saved/searches`; on `needs_review`,
   return the candidate without applying it; on `RETRYABLE`, keep the existing alert and
   reschedule the compile; on `REJECTED`, return the reason and store nothing. Register in
   `restmap.conf` / `web.conf`.
2. **Recompile / migrate**: an endpoint (or the existing "Consume KV" cadence) that reads
   existing alerts carrying a stored human original and recompiles them — both to migrate
   legacy `| tenxsearch` alerts to NATIVE, and to pick up template hashes that appeared after
   the alert was first saved.
3. **UI control**: a small addition to the setup/search page that calls `/tenx-alert` and
   surfaces `strategy` / `needs_review` / `reason` so a human confirms escape-hatch and
   flagged-passthrough cases before scheduling.
4. **Keep `| tenxsearch`** as the documented raw-text escape hatch (do not keep proxying jobs
   as the default).
5. **Live verification** (per the handoff): confirm the compiled saved search fires correctly
   as a scheduled alert, the hash prefilter matches, `| search` vs `search` stored forms
   behave identically under the scheduler, and time windows select the right buckets. Also
   verify the two builder blind spots above (fix `NOT` pruning and the `where_fields` string
   case, then relax the compiler's REJECT/needs_review guards accordingly), and confirm the
   `| tenxsearch searchstring="…"` escaping round-trips a value containing quotes and
   backslashes under `commands.conf` `chunked=true` parsing.

If a use case genuinely needs unchanged arbitrary SPL *and* original keyword semantics, the
only real answer is a decoded sidecar index — not search-time config. Call that out; don't try
to fake it.
