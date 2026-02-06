
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

10x_extraction_name = <string>
* Name of the search time field extraction for preping encoded events to be decoded

10x_extraction = <string>
* Regular expression for the search time field extraction for preping encoded events to be decoded
