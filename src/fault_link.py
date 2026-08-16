"""Inject / clear netem+HTB on the Mininet s1↔s2 core link only."""

from __future__ import annotations

from typing import Any, Optional


def core_link(net):
    for link in net.links:
        names = {link.intf1.node.name, link.intf2.node.name}
        if names == {"s1", "s2"}:
            return link
    raise RuntimeError("s1-s2 core link not found")


def port_index(intf_name: str) -> int:
    if "-eth" not in intf_name:
        raise ValueError(intf_name)
    return int(intf_name.rsplit("eth", 1)[-1])


def core_port_meta(link) -> dict[str, Any]:
    out = {}
    for intf in (link.intf1, link.intf2):
        sw = intf.node.name
        out[f"{sw}_core_intf"] = intf.name
        out[f"{sw}_core_port"] = port_index(intf.name)
    return out


def clear_core_qos(link) -> None:
    for intf in (link.intf1, link.intf2):
        intf.node.cmd(f"tc qdisc del dev {intf.name} root 2>/dev/null")


def apply_core_fault(
    link,
    bw_mbit: Optional[float] = None,
    delay: Optional[str] = None,
    loss_pct: Optional[float] = None,
) -> None:
    """Single-factor netem/HTB on both ends of s1-s2. None = unlimited / no netem."""
    clear_core_qos(link)
    kwargs: dict[str, Any] = {}
    if bw_mbit is not None:
        kwargs["bw"] = float(bw_mbit)
    if delay:
        kwargs["delay"] = delay
    if loss_pct is not None:
        kwargs["loss"] = float(loss_pct)
    if not kwargs:
        return
    link.intf1.config(**kwargs)
    link.intf2.config(**kwargs)
