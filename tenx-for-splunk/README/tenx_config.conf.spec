
# Spec for the 10x application custom config.
#
# See tenx_config.conf for more info.
#
[config]
dest_dml_index = <string>
* Name of the index for indexing processed (pure) 10x pattern data

dml_source_type = <string>
* Name of the searchable copy of 10x pattern data: the source of copies written with
  collect as sourcetype stash, and the sourcetype of copies an install already holds

collection_name = <string>
* Name of the KV collection for storing 10x pattern structure

timestamp_placeholder = <string>
* Placeholder for the timestamp in processed 10x pattern

variable_separator = <string>
* Variable separator in the raw 10x pattern

tenx_extraction_name = <string>
* props.conf key of the search-time extraction that splits a compact event into its hash and values

tenx_extraction = <string>
* transforms.conf stanza that extraction uses

replay_max_sourcetypes = <non-negative integer>
* At most this many original sourcetypes (indexed field tenx_sourcetype of compact events)
  get their search-time fields replayed by the tenx-replay macro; the least busy are left out
  and named in tenx_replay_command.log. 0 means no limit.
* Default: 200

replay_max_macro_chars = <non-negative integer>
* Largest tenx-replay macro definition tenxreplay writes, in characters, and the largest unit.
  Past it, source:: and host:: rules are limited to those matching a source or host seen, then
  the least busy original sourcetypes are left out; a unit past it replays nothing. 0 means no
  limit. Splunk sets no limit on a macro's length; it runs at most 1,000 commands in a search,
  so tenxreplay also keeps the macro and each unit to 900 commands, the same way.
* Default: 0

replay_expire_days = <non-negative integer>
* An original sourcetype that no rebuild has seen for this many days, and that no compact event
  of any date carries any longer, loses its replay at the next rebuild. 0 means never.
* Default: 400

field_narrowing = splunk|<boolean>
* How a field comparison after `tx` or `txf` (field=value, field IN (...)) narrows which compact
  events are expanded.
* splunk: the compact events must hold the index terms Splunk requires of raw events for the
  comparison, read from a probe search over a time range that holds no event. When they cannot
  be read, the comparison does not narrow, and the search shows a warning.
* true: like the value written as a word. Needs the [tenx:narrowing] list in tenx_replay.conf,
  which tenxreplay writes only while this is true and some compact event carries
  tenx_sourcetype. A field whose value is not text of the event and that the list does not name
  (a rule defined only in another app, or private to a user) can then make `tx` return fewer
  events than the same search on raw events.
* false: a field comparison does not narrow.
* Default: false
