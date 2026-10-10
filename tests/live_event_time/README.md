# Live check: event time and UTC rendering

Runs on a throwaway Splunk container, then scores offline.

```sh
# data: from log-10x/benchmarks, splunk-license/: ./run.sh data encode
git show v1.1.4:tenx-for-splunk/default/macros.conf > /tmp/macros-1.1.4.conf
tests/live_event_time/rig.sh <data dir> /tmp/macros-1.1.4.conf out
python3 tests/live_event_time/measure.py out <data dir>
docker rm -f -v tenx-event-time
```

- Event time: every compact event's `_time` against the timestamp Splunk itself extracts from
  the first line of that event's original text, before (the compact sourcetype as 1.1.4 set it)
  and after.
- UTC rendering: `fixture.py` writes four templates with a timestamp slot (ISO with
  milliseconds, comma milliseconds, 12-hour with AM/PM, an RFC 822 zone) and events every ten
  minutes for 14 hours either side of the 2026 daylight-saving transitions in New York, London,
  Sydney, Chatham and Adak, plus every six hours through 2026. Each is expanded by the old and the
  new macro for viewers in eight zones and compared with its UTC text.
