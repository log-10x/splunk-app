#!/bin/sh
# The clean-up job of the compact folder, as the README and the docs print it: it deletes the files of
# /opt/tenx/compact that the heavy forwarder reports as finished reading and that have not changed for
# $MINUTES minutes. /opt/tenx/splunk-auth is a curl config file that only root reads, holding a login of
# the heavy forwarder, for example: header = "Authorization: Bearer <token>"
curl -sk -K /opt/tenx/splunk-auth \
  "https://localhost:8089/services/admin/inputstatus/TailingProcessor:FileStatus?output_mode=json" |
  python3 -c 'import json, sys
for path, status in json.load(sys.stdin)["entry"][0]["content"]["inputs"].items():
    if status.get("type") == "finished reading":
        print(path)' > /opt/tenx/compact-finished.txt
find /opt/tenx/compact -type f -mmin +"$MINUTES" | grep -Fx -f /opt/tenx/compact-finished.txt |
  while read -r f; do rm -f "$f"; done
