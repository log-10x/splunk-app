#!/usr/bin/env python3
"""writer.py <source file> <file to grow> <lines> <lines per second> [lines to skip]: appends lines of the source to the
file at a fixed rate, flushed every half second."""
import sys
import time

src, dst, n, rate = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
skip = int(sys.argv[5]) if len(sys.argv) > 5 else 0
lines = []
with open(src, 'rb') as f:
	for i, line in enumerate(f):
		if i < skip:
			continue
		if len(lines) >= n:
			break
		lines.append(line)
start, done = time.time(), 0
with open(dst, 'ab') as out:
	while done < len(lines):
		want = min(len(lines), int((time.time() - start) * rate) + 1)
		if want > done:
			out.write(b''.join(lines[done:want]))
			out.flush()
			done = want
		time.sleep(0.5)
print('wrote', done, 'lines in', round(time.time() - start, 1), 's', flush=True)
