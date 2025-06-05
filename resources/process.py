#!/usr/bin/env python
import sys
import re
import csv
from collections import defaultdict
import argparse
import statistics
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("results_filename")
args = parser.parse_args()


LINE_REGEX = re.compile(
    r"\[\s*\d+\.\d+] wireguard: "
    "(?P<role>client|server to) "
    "\[(?P<client_public>[0-9a-f]+)\] "
    "completed handshake in (?P<time>\d+) ns")


handshakes = defaultdict(lambda: {"server": [], "client": []})


for line in sys.stdin:
    if not (match := LINE_REGEX.match(line.strip())):
        continue

    role = "client" if match.group("role") == "client" else "server"
    client_public = match.group("client_public")
    time = int(match.group("time"))

    handshakes[client_public][role].append(time)


with Path(args.results_filename).open("w") as fh:
    writer = csv.DictWriter(fh, fieldnames=["client_public", "role", "time"])
    writer.writeheader()
    for key, roles in handshakes.items():
        for role, hss in roles.items():
            for handshake in hss:
                writer.writerow({"client_public": key, "role": role, "time": handshake})

client_hs = [hs for pk, roles in handshakes.items() for hs in roles["client"]]
server_hs = [hs for pk, roles in handshakes.items() for hs in roles["server"]]

print(f"Got {len(client_hs)} client handshakes and {len(server_hs)} server handshakes")


print(f"Client median: {statistics.median(client_hs)}")
print(f"Client mean: {statistics.mean(client_hs)}")
print(f"Client variance: {statistics.pvariance(client_hs)}")
print(f"Client stdev: {statistics.pstdev(client_hs)}")
print(f"Server median: {statistics.median(server_hs)}")
print(f"Server mean: {statistics.mean(server_hs)}")
print(f"Server variance: {statistics.pvariance(server_hs)}")
print(f"Server stdev: {statistics.pstdev(server_hs)}")
