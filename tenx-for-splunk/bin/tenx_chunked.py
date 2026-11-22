"""
The chunked protocol (version 2) of a generating search command, for tenxprefilter.

Splunk Enterprise 10.4.3 starts such a command in a subsearch three times for one search, twice
only to ask for its settings (getinfo). Starting the Python SDK costs more than the prefilter's own
work, so tenxprefilter answers getinfo with this module alone and imports the rest only in the
start that runs.

The replies are the SDK's, byte for byte, for a generating command that writes one field.
"""
import json
import sys

GETINFO_REPLY = {"generating": True, "type": "stateful"}


def read_chunk(stream):
	"""(metadata, body) of the next chunk, or None at the end of the input."""
	header = stream.readline()
	if not header:
		return None
	_, meta, body = header.decode("ascii").strip().split(",")
	return json.loads(stream.read(int(meta)).decode("utf-8")), stream.read(int(body))


def write_chunk(stream, metadata, body=b""):
	meta = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
	stream.write(b"chunked 1.0,%d,%d\n" % (len(meta), len(body)) + meta + body)
	stream.flush()


def answer_getinfo(stdin=None, stdout=None):
	"""
	Reads the getinfo chunk and answers it. Returns its search information when an execute chunk
	follows, or None when the input ends there (a start that only asks for the settings).
	"""
	stdin, stdout = stdin or sys.stdin.buffer, stdout or sys.stdout.buffer
	first = read_chunk(stdin)
	if first is None or first[0].get("action") != "getinfo":
		return None
	write_chunk(stdout, GETINFO_REPLY)
	following = read_chunk(stdin)
	if following is None or following[0].get("action") != "execute":
		return None
	return first[0].get("searchinfo") or {}


def searchinfo(info):
	"""The search information as the SDK gives it: attributes, times as numbers, the search unquoted."""
	import types
	import urllib.parse
	info = dict(info)
	for key in ("earliest_time", "latest_time"):
		info[key] = float(info.get(key) or 0)
	info["search"] = urllib.parse.unquote(info.get("search") or "")
	return types.SimpleNamespace(**info)


class Exit(Exception):
	"""error_exit() of a running command."""


class GeneratingCommand(object):
	"""The part of the SDK's GeneratingCommand that tenxprefilter uses."""

	def __init__(self):
		import logging
		import types
		self._messages = []
		self._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace())
		if not logging.root.handlers:
			logging.root.addHandler(logging.StreamHandler())
		self.logger = logging.getLogger(type(self).__name__)

	def write_warning(self, message):
		self._messages.append(["WARN", message])

	def error_exit(self, error, message=None):
		self._messages.append(["ERROR", str(error) if message is None else message])
		self.logger.error("Abnormal exit: %s", error)
		raise Exit()

	def generate(self):
		return iter(())


def rows_body(rows):
	"""The rows as the SDK writes them: CSV with an empty __mv_ column beside each field."""
	import csv
	import io
	if not rows:
		return b""
	names = []
	for row in rows:
		names.extend(n for n in row if n not in names)
	text = io.StringIO()
	writer = csv.writer(text, lineterminator="\r\n")
	writer.writerow([c for n in names for c in (n, "__mv_" + n)])
	for row in rows:
		writer.writerow([c for n in names for c in (row.get(n, ""), "")])
	return text.getvalue().encode("utf-8")


def run(command_class, info, stdout=None):
	"""Runs the command for the execute chunk and writes its rows; an error stops the search with its message."""
	stdout = stdout or sys.stdout.buffer
	command = command_class()
	command._metadata.searchinfo = searchinfo(info)
	try:
		body = rows_body(list(command.generate()))
	except Exit:
		write_chunk(stdout, {"inspector": {"messages": command._messages}, "finished": True})
		sys.exit(1)
	except Exception as e:
		command.logger.exception("Abnormal exit")
		command._messages.append(["ERROR", "Error in '%s' command: %s" % (info.get("command") or "tenxprefilter", e)])
		write_chunk(stdout, {"inspector": {"messages": command._messages}, "finished": True})
		sys.exit(1)
	metadata = {"inspector": {"messages": command._messages}, "finished": True} if command._messages else {"finished": True}
	write_chunk(stdout, metadata, body)
