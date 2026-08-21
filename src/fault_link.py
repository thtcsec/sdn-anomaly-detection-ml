"""Inject / clear netem+HTB on the Mininet s1↔s2 core link only.

Must use explicit ``tc`` on the OVS port devices. Mininet's default ``Intf``
(not ``TCIntf``/``TCLink``) ignores bw/delay/loss in ``intf.config()``, which
is why Protocol D 4-class collapsed: labels changed, the datapath did not.
"""

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
    return int(intf_name.rsplit("eth", 1)[1])


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
        intf.node.cmd(f"tc qdisc del dev {intf.name} ingress 2>/dev/null")


def show_core_qdisc(link) -> str:
    lines = []
    for intf in (link.intf1, link.intf2):
        out = intf.node.cmd(f"tc qdisc show dev {intf.name}").strip()
        lines.append(f"{intf.name}: {out or '(no qdisc)'}")
    return " | ".join(lines)


def apply_core_fault(
    link,
    bw_mbit: Optional[float] = None,
    delay: Optional[str] = None,
    loss_pct: Optional[float] = None,
) -> str:
    """Single-factor netem/HTB on both ends of s1-s2. None = no impairment.

    Bandwidth uses HTB (rate ceiling). Loss/delay use netem. Applied with
    ``tc`` on the switch port, not ``Intf.config``.
    """
    clear_core_qos(link)
    if bw_mbit is None and not delay and loss_pct is None:
        return show_core_qdisc(link)

    delay_s = str(delay).strip() if delay else ""
    for intf in (link.intf1, link.intf2):
        dev = intf.name
        node = intf.node
        if bw_mbit is not None:
            rate = f"{float(bw_mbit):g}mbit"
            # Burst large enough that ICMP probes pass; iperf still hits the ceiling.
            node.cmd(f"tc qdisc replace dev {dev} root handle 1: htb default 10")
            node.cmd(
                f"tc class add dev {dev} parent 1: classid 1:10 htb "
                f"rate {rate} ceil {rate} burst 32k cburst 32k"
            )
            netem = []
            if delay_s:
                netem.append(f"delay {delay_s}")
            if loss_pct is not None:
                netem.append(f"loss {float(loss_pct):g}%")
            if netem:
                node.cmd(
                    f"tc qdisc add dev {dev} parent 1:10 handle 10: netem {' '.join(netem)}"
                )
            else:
                # Short queue: rate ceiling without 600ms bufferbloat (which looks like Delay).
                node.cmd(f"tc qdisc add dev {dev} parent 1:10 handle 10: pfifo limit 5")
        else:
            parts = ["netem"]
            if delay_s:
                parts.append(f"delay {delay_s}")
            if loss_pct is not None:
                parts.append(f"loss {float(loss_pct):g}%")
            node.cmd(f"tc qdisc replace dev {dev} root {' '.join(parts)}")
    return show_core_qdisc(link)
