from __future__ import annotations

import json
from typing import Any
from itertools import product, chain, groupby
import re
from operator import itemgetter
from pathlib import Path

from invoke import task
from rich import print as pprint
from rich.console import Console


_console = Console()
_directions = ["incoming", "outgoing"]

_RELAYS = Path("relays.json")
_RULES = Path("syncthing-relays-allowlist.lsrules")


@task
def refresh_relays_list(c):
    _console.rule("[bold blue]Obtaining fresh relays endpoint list[/bold blue]")
    c.run(f"curl -o '{_RELAYS}' 'https://relays.syncthing.net/endpoint'")


def _allow(**kwargs):
    return {
        "process": "/Applications/Syncthing.app/Contents/MacOS/Syncthing",
        "action": "allow",
    } | kwargs


def _rules_sync_traffic():
    protocols = ["tcp", "udp"]
    for protocol, direction in product(protocols, _directions):
        yield _allow(
            notes=f"{protocol} based sync protocol traffic",
            direction=direction,
            protocol=protocol,
            ports="22000",
            remote="any",
        )


def _rules_local_discovery():
    yield _allow(
        **{
            "ports": "1900",
            "remote-addresses": "239.255.255.250",
        }
    )
    for direction in _directions:
        yield _allow(
            notes="for discovery broadcasts on IPv4 and multicasts on IPv6",
            direction=direction,
            protocol="udp",
            ports="21027",
            remote="local-net",
        )


def _rules_stun_servers():
    yield _allow(
        **{
            "notes": "stun servers :3478, from docs: https://docs.syncthing.net/users/config.html#config-option-options.stunserver",
            "direction": "outgoing",
            "protocol": "udp",
            "ports": "3478",
            "remote-domains": [
                "stun.callwithus.com",
                "stun.counterpath.com",
                "stun.counterpath.net",
                "stun.ekiga.net",
                "stun.ideasip.com",
                "stun.internetcalls.com",
                "stun.schlund.de",
                "stun.sipgate.net",
                "stun.voip.aebc.com",
                "stun.voiparound.com",
                "stun.voipbuster.com",
                "stun.voipstunt.com",
                "stun.xten.com",
            ],
        }
    )


def _process_relay(relay: dict):
    m = re.fullmatch(r"relay://(\d+\.\d+\.\d+\.\d+):(\d+)/.*", relay["url"])
    return m.groups()


def _rules_relays():
    with _RELAYS.open() as fh:
        endpoints = json.load(fh)

    relays = [_process_relay(relay) for relay in endpoints["relays"]]
    relays = [(ip, int(port)) for ip, port in relays]
    relays = sorted(relays, key=itemgetter(1))
    for port, relay_group in groupby(relays, key=itemgetter(1)):
        ip_list = ', '.join(ip for ip, _port in relay_group)
        for direction in _directions:
            yield _allow(
                **{
                    "notes": f"Relay :{port}",
                    "direction": direction,
                    "protocol": "tcp",
                    "ports": port,
                    "remote-addresses": ip_list,
                }
            )


@task
def generate_rules(c):
    _console.rule("[bold blue]Generating LittleSnitch rules file[/bold blue]")
    d = {
        "description": "Allow the syncthing-macos app to work",
        "name": "syncthing-macos",
        "rules": list(
            chain(
                _rules_sync_traffic(),
                _rules_local_discovery(),
                _rules_stun_servers(),
                _rules_relays(),
            )
        ),
    }
    with _RULES.open("w") as fh:
        json.dump(d, fh, indent=2)
