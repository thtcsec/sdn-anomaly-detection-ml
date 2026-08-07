"""
Lab safety guards for Mininet-isolated traffic generation.

Blocks any attack target outside the pre-approved Mininet host IPs.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable

from provenance_schema import ALLOWED_LAB_CIDR, ALLOWED_LAB_IPV4


def is_allowed_lab_ip(ip: str) -> bool:
    ip = str(ip).strip()
    if ip in ALLOWED_LAB_IPV4:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        net = ipaddress.ip_network(ALLOWED_LAB_CIDR, strict=False)
        return addr in net and not addr.is_global
    except ValueError:
        return False


def assert_lab_targets(targets: Iterable[str], context: str = '') -> None:
    bad = [t for t in targets if not is_allowed_lab_ip(t)]
    if bad:
        raise RuntimeError(
            f'[SAFETY] Refusing traffic outside Mininet lab IPs {sorted(ALLOWED_LAB_IPV4)}. '
            f'Blocked targets={bad}. {context}'
        )


def assert_no_default_route_hint(cmd: str) -> None:
    """Best-effort textual guard — still rely on IP allowlist."""
    lowered = cmd.lower()
    forbidden = ['8.8.8.8', '1.1.1.1', '0.0.0.0', '255.255.255.255', 'google', 'cloudflare']
    for token in forbidden:
        if token in lowered:
            raise RuntimeError(f'[SAFETY] Forbidden token in command: {token!r} | cmd={cmd!r}')
