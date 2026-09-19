# The 10x Search view without Mako

Design note, 2026-09-19. What the app's search tab is built on, what Splunk is
removing, what can replace it, and what was measured on live Splunk to choose.

## Why this exists

The app's "10x Search" tab, the page its navigation opens by default, is a
`type="html"` view backed by a fifteen-line Mako template. Splunk Enterprise 10.4
deprecates custom Mako templates shipped by apps and says they "will be removed
in future versions". No removal version is named. What is named is a switch:
`deactivate_custom_mako_templates` in `web-features.conf`, off by default, which
lets an administrator block app-shipped templates today. When it is on, or when
the removal lands, that tab stops rendering.

Nothing is wrong today. The tab works on 9.4 and 10.4, and AppInspect reports
the template as a warning, not a failure. This is a scheduled removal with an
unknown date and a switch that brings it forward, and the app should stop
depending on it before either happens.

## What the tab is

Less than it looks. The template inherits Splunk's base page for the chrome,
draws three empty placeholder divs, prints "Loading...", and loads one script.
That script requires two modules: the search hook, which rewrites every search
job POST from `/search/jobs` to `/tenx-search` so the endpoint can resolve the
user's terms against the template store and expand the results; and a page
module whose whole job is to append a red warning to Splunk's search title when
no sourcetype is marked as carrying compact events.

The hook is the only thing the template does that matters, and the template
only loads it because the tab is an HTML view rather than a dashboard. The app's
`dashboard.js` applies the hook to every dashboard in the app automatically;
an HTML view is outside that, so the template loads the hook by hand. That
script tag is the same one that named an app which does not exist and returned
404 until #16.

**And the tab does not work.** Rendered in headless Chrome on Splunk 9.4.15
with the app from `main`, it shows the Splunk bar and the word "Loading..." and
nothing else: eighteen characters of body text, no search bar, no time picker,
no hook, and one page error, `ReferenceError: require is not defined`. The
page never changes after that. The reason is in the template's first line. It
inherits `pages/base.html`, which draws the chrome and then loads the bundle
named after the view, `build/pages/enterprise/search.js`, but the search bundle
does not mount into the base page's placeholders. Splunk's own search view
inherits a different first-party template for exactly that reason, and that
template carries the comment "do not use this inherit pattern for other
individually bundled pages". The app's script then runs on a page with no
module loader and throws on its first token.

So there is nothing to preserve. The tab has been a blank page on every
version the app has shipped on: before #16 its script was a 404, and after #16
the script loads and fails. What the earlier asset check proved was that the
file resolves, which was necessary and not sufficient. The app's Compile Alert
view, a classic dashboard three files away, renders completely on the same
instance with the hook installed by `dashboard.js`.

## What Splunk says, with sources

The 10.4 release notes deprecate custom Mako templates and custom CherryPy
controllers in the same breath, name no replacement for either, and name no
removal version. The same page removes two older things that matter here: HTML
dashboards, meaning the old convert-a-dashboard-to-HTML feature, are gone in
10.4 with "use Dashboard Studio" as the instruction, and jQuery 2 is gone, so a
classic dashboard still declaring `version="1.0"` no longer loads. All three of
this app's dashboards declare 1.1.

The switch is documented in the 10.4 `web-features.conf` reference under
`[feature:appserver_security]`: `deactivate_custom_mako_templates`, default
false, "whether or not Splunk Web blocks custom Mako templates shipped by apps",
with the note that Splunk's own templates under `share/splunk/search_mrsparkle`
are always allowed. The 10.2 release note announcing it spells the key
`disable_custom_mako_templates`. Its sibling for CherryPy controllers affects
only `/custom/<app>/*` routes and explicitly not REST endpoints, views,
dashboards or static assets, which is why this app's three REST handlers are
untouched by any of this.

Splunk's own migration advice comes from the page on the removed HTML
dashboards, and it lists three destinations: Dashboard Studio, described as
preferred; Simple XML extended with custom JavaScript; and a custom single-page
application declared as `<view template="app:/template/path" type="html">`. The
third is exactly what this app does today, and it is the mechanism 10.4 has now
deprecated. Dashboard Studio takes no custom JavaScript at all. That leaves one
supported destination for a page that needs to run its own script, and it is
the one this app already uses for its Compile Alert view: a classic dashboard
with a `script` attribute.

UCC, the framework Splunk generates its own add-ons with, took a fourth road. It
removed Mako by making its page template plain HTML with values filled in at
build time, loading Splunk's configuration and translation bundles by relative
URL and then its own entry module, and drawing its own chrome. That template
inherits nothing from Splunk Web: a whole application shipped as static
files, not a page that borrows Splunk's search UI.

One more fact decides how AppInspect sees all this. Run locally on two
variants, the checker reported "No custom Mako template files found" both for a
`type="html"` view whose template contains no Mako syntax and for the view
replaced by a dashboard. The checker classifies a template by its content,
not by the view type or where the file sits.

## The candidates

**A. Keep the HTML view, strip the template to plain HTML.** No inherit, no
Python block, no `${}`; a hardcoded script path. UCC's road, and one that
passes AppInspect today. What it loses is the inheritance from Splunk's base page,
which is where the chrome and the search UI came from, so the page would have
to build everything itself. Whether Splunk Web even renders it once the switch
is on is the first thing to measure.

**B. Make the view a classic dashboard.** A `<form version="1.1">` with a text
input, a time picker and an events panel, plus a `script` for the configuration
warning. The hook arrives for free through `dashboard.js`, which already covers
every dashboard in the app, so the by-hand script tag that caused the 404 goes
away with the template. Works on 9.4 through 10.4 today and is the one
destination Splunk still documents for custom script. What it gives up is
Splunk's own search page: no search assistant, no field sidebar, no save-as
flows on that tab.

**C. No view override at all, hook Splunk's own search page.** Delete `search.xml`
and let the app's nav entry fall through to Splunk's own search view, then get
the hook onto it some other way. The only candidate mechanism is
`appserver/static/application.js`, which older Splunk loaded on every page of
an app. Whether current Splunk still does is a yes or no question a render
answers. If yes, this is the best outcome: Splunk's own search page, expanded,
with no template. If no, C is not available.

**D. Dashboard Studio.** Preferred by Splunk, and unable to run the hook. A
Studio page for this tab would be a search box that returns compact events.
Not a candidate for this feature.

**E. No page at all: the generating command.** `| tenxsearch
searchstring="..."` already exists, resolves terms to template hashes and
streams expanded results, and needs no browser, no hook and no template. The
command is slower than the endpoint for interactive use, which is why the
endpoint exists, and is also the one path that survives every UI deprecation
Splunk could make, so the design has to say what its role is even if it is not
the tab.

## How it was measured

Every render is headless Chrome, driven by Playwright, logging in to a live
Splunk started by the benchmark harness with the app installed, opening
`/app/tenx-for-splunk/search`, waiting eight seconds, screenshotting, and
reading a fixed set of signals out of the page: the title, whether a search
bar or a dashboard body is present, whether "Loading..." is still on screen,
whether the hook's `beforeSend` is installed on jQuery, whether an
`application.js` marker ran, the console errors, and every POST the page made
that mentions `/search/jobs` or `/tenx-search`. Where a search term is given,
the script types a search, runs it and reports how many times the term appears
in the rendered results and which endpoint the job was posted to. The 9.4 arm
has the E21 capture ingested and its KV store filled, so a search there proves
expansion end to end; the 10.4 arm has the app installed and no data, because
the question there is whether a page renders at all with the switch on.

The switch is applied by writing `web-features.conf` into `system/local` with
both spellings of the key and restarting Splunk, so a candidate is rendered
twice, once in today's world and once in the one where Splunk has removed
custom Mako.

## What was measured

The first render, on Splunk 9.4.15 with the app from `main`, is the finding
above: the tab is blank and always has been. The rest is the matrix on Splunk
10.4.3, every candidate rendered twice, with the switch off and then on. The
switch is `deactivate_custom_mako_templates`, which is the spelling 10.4's own
`web-features.conf.spec` carries on line 640.

| Candidate | Switch off | Switch on |
|---|---|---|
| Shipped, the Mako template | "Loading...", `require is not defined` | Splunk's **"Page Unavailable"** error page |
| A, same view, template with no Mako syntax | renders the app's own title and nothing else; `i18n_register is not defined` | **"Page Unavailable"** |
| B, classic dashboard form | "10x Search", dashboard body present, hook installed by `dashboard.js` | **identical** |
| C, no view override, `application.js` | Splunk's own search page, rendered inside the app; `application.js` never ran | identical |

Four things follow, and each closes a candidate or a question.

**The switch blocks every app-shipped template, not Mako syntax.** Variant A's
template contains no Mako at all, passes AppInspect as "no custom Mako
template files found", and is refused just the same. Whatever UCC does to ship
its plain-HTML page, it is not this view mechanism. A is out twice over: it
cannot host the hook, because nothing on that page defines a module loader, and
it does not survive the switch.

**Splunk no longer loads `application.js`.** With no view override, the tab
falls through to Splunk's own search page rendered under the app's
navigation, which is a good page, and the marker in `application.js` never
set. The first pass read the hook as installed there; that was Splunk's own
`beforeSend`, which carries its CSRF header, and the signal now requires the
app's endpoint name in the handler's source. C is out. There is no supported
way to run the app's script on Splunk's search page.

**The dashboard does not notice the switch.** B renders byte-for-byte the same
with it off and on: title, body, hook. That is the whole point of choosing the
mechanism Splunk still documents.

**Nothing version-specific is needed.** A classic `version="1.1"` dashboard is
what the app's Compile Alert view already is, and that view rendered with the
hook installed on 9.4.15 in the first render of the night. The replacement
works on the floor of the supported range and in the future past the removal,
from one file.

TO FILL: the search typed through the form, on 9.4 and on 10.4 with the switch
on, after the readiness fix.

## The decision

**The 10x Search tab becomes a classic dashboard, and the app ships no
template of any kind.** Candidate B.

The elimination is short. A cannot run the hook and does not survive the
switch. C's mechanism no longer exists. D cannot run script. E is not a page.
B is the one destination Splunk still documents for a page that runs its own
script, it is what three of the app's four views already are, it inherits the
hook from `dashboard.js` without a by-hand include, and it renders identically
whether or not custom templates are blocked.

What it costs is honest to state and turns out to be nothing. The dashboard is
not Splunk's search page: no search assistant, no field sidebar, no save-as on
that tab. But the tab was never Splunk's search page either. What shipped was
a blank page with the word "Loading..." on it, on every version, and the assumption it
was built on, that an app view can host the search bundle, is one Splunk's own
templates reject. Measured against what shipped, the dashboard is not a
compromise. The tab works for the first time.

Two things are deliberately not attempted. The tab does not try to reproduce
Splunk's search experience inside a dashboard, because the pieces that make it
that experience are not available to a dashboard and a half-copy would be
worse than a plain form. And the app does not try to reach Splunk's own
search page any other way, because the render shows there is no way left, and
the next one to be invented would be the next one to be deprecated.

For someone who wants Splunk's own search page with expansion, the answer is the
one that needs no page at all: `| tenxsearch searchstring="..."` in any search
bar on any version, Studio included. It is slower than the endpoint, which is
why the tab exists, and it is the path that outlives every UI decision Splunk
makes.

## What "support for both" means here

Nothing version-specific, and that is the finding rather than a shortcut.

The question assumed the successor to Mako would be something older Splunk
lacks, so the app would carry a Mako page for old versions and the new thing
for new ones. The measurement says otherwise. The successor is a classic
dashboard, which Splunk 9.4 renders exactly as 10.4 does, and the Mako page
has nothing to offer on any version because it never rendered. So "both" is
one file, `search.xml`, that is the same on the floor of the supported range
and after the removal lands. There is no switch to read, no version to detect,
and no second copy of the tab to keep in step.

There is a second sense of "both" worth being explicit about, because it is
where the next deprecation would land. The app depends on custom JavaScript
in classic dashboards, for the hook, and Splunk's stated preference is
Dashboard Studio, which runs none. Classic dashboards are supported today and
only their PDF export is deprecated, so this is not imminent. But it is the
one dependency left, and the design should keep it thin: the dashboard is a
search box and an events panel and nothing that could not be rebuilt in an
afternoon, and the generating command, which needs no dashboard at all, stays
a first-class, documented way to search. If classic dashboards are ever
retired, the tab goes and the command remains, and the app has lost a
convenience rather than a capability.

What the app must never do again is ship a page whose life depends on Splunk
Web executing something the app wrote on the server. That is what a Mako
template is, it is what a CherryPy controller is, and both were deprecated on
the same day.

## What changes in the app

Branch `fix/search-view-without-mako`, five files and two deletions.

- `default/data/ui/views/search.xml` becomes a `<form version="1.1">` with a
  search input defaulting to the compact index, a time picker, a notice panel
  and an events panel. Same view name, so the nav entry and the default-search
  marker are untouched and the tab's URL does not change.
- `appserver/static/tenx_search_view.js` is the dashboard's script. It does not
  install the hook, because `dashboard.js` already has; it runs the
  configuration check against the notice panel.
- `javascript/views/tenx_search_page.js`: `checkConfig` takes a target
  selector, since a dashboard has no `.search-title` to append to.
- `appserver/static/pages/tenx_template_slim.html` and
  `javascript/tenx_search.js` are deleted. The template was the Mako; the loader
  existed only to be loaded by it.
- `dashboard.js`'s comment, which named the template as the example of a page
  that loads the hook by hand, now says there is no such page.
- `tests/live_render.js`, a browser render of any view, reporting the signals
  that decide whether a page is alive. It is the check that would have caught
  the blank tab on the day it shipped.

Nothing in `bin/` changes. The REST handlers, the KV alert, the generating
command and the macros are unaffected, and so is every measurement in the E21
benchmark. AppInspect on the branch: 0 errors, 0 failures, 0 future failures,
and the Mako warning is gone because there is nothing for it to find.
