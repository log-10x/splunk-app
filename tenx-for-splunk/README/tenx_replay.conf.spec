
# Spec for the field-replay lists written by the tenxreplay command.
#
# One stanza per original sourcetype seen on compact events (the indexed field tenx_sourcetype).
# Written by `| tenxreplay`; not meant to be edited by hand.
#
[<sourcetype>]
computed_fields = <comma-separated list>
* Fields that a calculated field (EVAL-) or an automatic lookup (LOOKUP-) produces for events of
  this sourcetype. Their values are not in the event text, so a search term on one of them
  cannot narrow the compact events by text.

aliased_fields = <comma-separated list>
* Fields that a field alias (FIELDALIAS-) produces for events of this sourcetype.

masked_at_index_time = <comma-separated list>
* The index-time rules that change the text of this sourcetype's events: SEDCMD- keys, and
  TRANSFORMS- classes whose transform sets DEST_KEY = _raw, in its own props stanza and the
  source:: and host:: stanzas recorded for it. Splunk does not run them on compact events, which
  are parsed as the compact sourcetype, so the values they mask are stored as sent and `tx`
  shows them unmasked. Empty when there are none. The Diagnostics dashboard lists them.

sources = <comma-separated list>|*
* The sources of this sourcetype's compact events: every source a rebuild has seen with it, or *
  when there were more than 200 or a name could not be listed. `| tenxreplay only_new=true`
  rebuilds the replay when a source not listed here appears.

hosts = <comma-separated list>|*
* The hosts of this sourcetype's compact events: every host a rebuild has seen with it (a
  sourcetype seen for the first time: over all time), or * past 200 or when a name could not be
  listed. The sourcetype's own replay macro (txf(<sourcetype>), the search rewrite) applies the
  host:: stanzas matching one of them, and the source:: stanzas matching one of `sources`.
  `| tenxreplay only_new=true` rebuilds the replay when a host not listed here appears.

indexes = <comma-separated list>|*
* The indexes holding this sourcetype's compact events, kept like `hosts`. The search rewrite
  (dashboard hook, | tx, compiled alerts) replays the sourcetypes listed for the indexes a search
  names, and nothing when none is.

unit = <macro name>
* The macro that replays this sourcetype alone (tenx-replay-u<hash>); txf(<sourcetype>) reaches it
  through tenx-replay-st-<sourcetype>.

commands = <integer>
* The top-level commands of this sourcetype's unit. The search rewrite chains the units of the
  sourcetypes listed for the indexes a search names while the chain holds at most 900 commands,
  as Splunk runs no search of more than 1,000; past that, or when this is empty, it runs
  tenx-replay.

left_out = txf|unit|txf,unit|<empty>
* txf: the tenx-replay macro, which `txf` runs, leaves this sourcetype out, because the busier
  sourcetypes fill replay_max_macro_chars (tenx_config.conf) or the 900 commands the macro may
  hold; its unit still replays it, and the search rewrite chains its unit for the indexes listed
  here, within the limit under `commands`. unit: its own unit is over those limits and replays
  nothing. `txf` and txf(<sourcetype>) show a warning in either case. Empty: neither.

last_seen = <epoch seconds>
* Start of the UTC day a rebuild last saw a compact event of this sourcetype. The replay of a
  sourcetype not seen for replay_expire_days (tenx_config.conf) is removed once no compact event
  of any date carries it.

[tenx:narrowing]
fields_not_in_text = <comma-separated list>
* Fields that some props stanza gives a value not taken from the event's text: calculated
  fields, lookup outputs, extractions from metadata, aliases of those, and the indexed fields of
  compact events. The tx prefilter does not narrow a field comparison on these. * alone: on none.

[tenx:plan]
generation = <8 hex digits>
rules = <JSON list>
* The rules of the tenx-replay macro, for `txf` to replay only those that feed the fields a search
  reads: [id, fields written, fields read, needs the source:: and host:: stanza tests] each. Used
  only with the macro of the same generation.
