#!/bin/python

import sys

for line in sys.stdin:
    # Split off comments
    if "#" in line:
        line, _ = line.split("#", 1)
    if "=" in line:
        key, value = line.split("=", 1)
    else:
        key = line
        value = ""

    print(f"key=\"{key.strip()}\"")
    print(f"value=\"{value.strip()}\"")

