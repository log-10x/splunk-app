
[tenx_dml_to_kv]
python.version = python3

param.source = <string>
* The event search that finds template records. The alert action adds an index-time range to it
  and reads the records itself.
* Default: index=tenx_dml sourcetype=tenx_dml_raw_json

param.from = <string>
* An index time, in epoch seconds, to load template records from instead of the checkpoint the
  action keeps; 0 loads every record in the index. Empty: from the checkpoint.
* Default: empty
