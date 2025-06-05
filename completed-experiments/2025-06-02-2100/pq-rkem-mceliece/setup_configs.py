#!/bin/python

from contextlib import nullcontext
import subprocess
from pathlib import Path
from typing import Tuple


NUM_EXPERIMENTS: int = 2


def generate_keys() -> Tuple[Tuple[str, str], Tuple[str, str]]:
    result = subprocess.check_output(["./wg", "genkey"], text=True)
    ipk = None
    isk = None
    rpk = None
    rsk = None
    for line in result.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        if line.startswith("ResponderPublicKey"):
            _, rpk = line.split(" = ", 1)
        elif line.startswith("ResponderPrivateKey"):
            _, rsk = line.split(" = ", 1)
        elif line.startswith("InitiatorPrivateKey"):
            _, isk = line.split(" = ", 1)
        elif line.startswith("InitiatorPublicKey"):
            _, ipk = line.split(" = ", 1)

    if ipk is None or isk is None or rpk is None or rsk is None:
        raise ValueError("Didn't get one of the keys?")

    return ((ipk, isk), (rpk, rsk))


def setup_experiment():

    for idx in range(NUM_EXPERIMENTS):
        ((ipk, isk), (rpk, rsk)) = generate_keys()
        serverconf = f"""
[Interface]
Address = 10.{100+idx}.0.1/24
ListenPort = 51820
ResponderPrivateKey =   {rsk}
ResponderPublicKey =    {rpk}

[Peer]
InitiatorPublicKey =   {ipk}
AllowedIPs = 10.{100+idx}.0.{2}/32
"""

        clientconf = f"""[Interface]
Address = 10.{100 + idx}.0.{2}/24
InitiatorPrivateKey = {isk}
InitiatorPublicKey = {ipk}

[Peer]
ResponderPublicKey = {rpk}
Endpoint = 10.{20 + idx}.0.1:51820
AllowedIPs = 10.{100 + idx}.0.1/32"""

        Path(f"client{idx}.conf").write_text(clientconf)
        Path(f"server{idx}.conf").write_text(serverconf)


if __name__ == "__main__":
    if not Path("./wg").exists() or not Path("wireguard.ko").exists():
        print("Execute me from the experiment folder that I'm in!")

    setup_experiment()
