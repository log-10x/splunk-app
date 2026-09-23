
# Spec for the 10x application custom config.
#
# See tenx_config.conf for more info.
#
[config]
dest_dml_index = <string>
* Name of the index for indexing processed (pure) 10x pattern data

dml_source_type = <string>
* Name of the sourcetype for indexing processed (pure) 10x pattern data

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
