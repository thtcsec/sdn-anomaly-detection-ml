"""Pure mitigation policy helpers, independent of os-ken."""

from __future__ import annotations

# Three completed polls with a source-level alert → OpenFlow DROP.
DEFAULT_ALERT_THRESHOLD = 3
# DROP match priority (above L2/L3 forwarding entries at priority 1).
BLOCK_FLOW_PRIORITY = 1000

# Demo/thesis fabric: h1–h3 are servers/victims — never auto-DROP them.
PROTECTED_VICTIM_IPS = frozenset({"10.0.0.1", "10.0.0.2", "10.0.0.3"})
# RF may label idle ICMP ANOMALY; only streak sources with a flood-sized packet delta this poll (not LOSO).
MIN_FLOOD_DELTA_PACKETS = 30
# Cap RF inferences per completed OpenFlow poll so a 5s cycle can finish
# during SYN-flood (tens of thousands of microflows). Sampling is a realtime
# budget, not a change to offline LOSO.
MAX_ML_FLOWS_PER_POLL = 256


def is_flood_source(ip_src, delta_packets, protected=None, min_delta=None):
    """True if this src is an auto-block candidate (flood volume, not a victim host)."""
    protected = PROTECTED_VICTIM_IPS if protected is None else protected
    min_delta = MIN_FLOOD_DELTA_PACKETS if min_delta is None else min_delta
    if str(ip_src) in protected:
        return False
    return int(delta_packets or 0) >= int(min_delta)


def aggregate_ip_stats(flows):
    """Sum packet_delta and flow count per ip_src over the full dump (not the ML cap)."""
    deltas = {}
    counts = {}
    for item in flows or ():
        ip = str(item.get("ip_src") or "")
        if not ip:
            continue
        deltas[ip] = int(deltas.get(ip, 0)) + int(item.get("packet_delta") or 0)
        counts[ip] = int(counts.get(ip, 0)) + 1
    return deltas, counts


def select_streak_ips(
    anomalous_ips,
    delta_packets_by_ip,
    protected=None,
    min_delta=None,
    skipped_ml_ips=None,
    flow_count_by_ip=None,
):
    """ANOMALY sources that may increment the 3-poll DROP streak this cycle.

    Volume is per source IP across the whole dump: many 1-packet SYN microflows
    still count when their summed packet_delta is flood-sized (≥30), even if
    every individual 5-tuple is below that. A src also qualifies if some of
    its flows were skipped by the per-poll ML cap and the aggregate is already
    flood-sized.
    """
    deltas = delta_packets_by_ip or {}
    counts = flow_count_by_ip or {}
    chosen = {
        str(ip)
        for ip in anomalous_ips
        if is_flood_source(
            ip,
            _src_flood_volume(str(ip), deltas, counts),
            protected,
            min_delta,
        )
    }
    for ip in skipped_ml_ips or ():
        ip = str(ip)
        if is_flood_source(ip, _src_flood_volume(ip, deltas, counts), protected, min_delta):
            chosen.add(ip)
    return chosen


def _src_flood_volume(ip, deltas, counts):
    """Per-IP flood size: summed packet_delta, or microflow count if deltas were 0.

    hping random-sport SYNs are 1-packet 5-tuples. Overlapping dumps often report
    packet_delta=0 for those rows even while the table still holds tens of
    thousands of flows from that src — count them as volume, not as a miss.
    """
    return max(int(deltas.get(ip, 0) or 0), int(counts.get(ip, 0) or 0))


def _positive_streak_ips(tracked_streak_ips):
    """IPs that already have a consecutive-poll streak in progress."""
    tracked = tracked_streak_ips or {}
    if hasattr(tracked, "items"):
        return {str(ip) for ip, n in tracked.items() if int(n or 0) > 0}
    return {str(ip) for ip in tracked}


def select_hold_ips(
    observed_ips,
    flood_ips,
    delta_packets_by_ip=None,
    flow_count_by_ip=None,
    skipped_ml_ips=None,
    incomplete=False,
    poll_delta_packets=0,
    tracked_streak_ips=None,
):
    """Attacker IPs whose overload/stale dump still counts as a consecutive poll.

    This is not a miss: the src is still present as the attacker (many flows,
    last poll already had a streak, or the dump did not finish). Callers must
    increment these IPs — freezing at 2/3 is forbidden. Victim hosts h1–h3
    are never held.
    """
    protected = PROTECTED_VICTIM_IPS
    observed = {str(ip) for ip in (observed_ips or ())} - protected
    flood = {str(ip) for ip in (flood_ips or ())}
    skipped = {str(ip) for ip in (skipped_ml_ips or ())}
    deltas = delta_packets_by_ip or {}
    counts = flow_count_by_ip or {}
    ongoing = _positive_streak_ips(tracked_streak_ips) - protected
    hold = set(ongoing) if incomplete else set()
    ingested = sum(int(v or 0) for v in counts.values())
    pps_dead = int(poll_delta_packets or 0) <= 0
    for ip in observed:
        if ip in flood:
            continue
        n_flows = int(counts.get(ip, 0) or 0)
        n_delta = int(deltas.get(ip, 0) or 0)
        # Busy table, no measured increment: overlapping dump or idle 1-packet SYNs.
        if n_flows >= MIN_FLOOD_DELTA_PACKETS and n_delta < MIN_FLOOD_DELTA_PACKETS:
            hold.add(ip)
        elif ip in skipped:
            hold.add(ip)
        elif pps_dead and n_flows > 0 and ingested >= MIN_FLOOD_DELTA_PACKETS:
            hold.add(ip)
        elif ip in ongoing and n_flows > 0 and n_delta < MIN_FLOOD_DELTA_PACKETS and pps_dead:
            hold.add(ip)
    return hold - flood


def select_ml_flows(flows, max_n=None):
    """Return indices of at most max_n flows to score this poll.

    Prefer highest packet_delta this poll, then packet_count. Unscored flows
    still count toward poll_pps / per-src deltas; they are not a LOSO change.
    """
    max_n = MAX_ML_FLOWS_PER_POLL if max_n is None else int(max_n)
    if max_n <= 0 or not flows:
        return []
    n = len(flows)
    if n <= max_n:
        return list(range(n))
    ranked = sorted(
        range(n),
        key=lambda i: (
            int(flows[i].get("packet_delta") or 0),
            int(flows[i].get("packet_count") or 0),
        ),
        reverse=True,
    )
    return ranked[:max_n]


def update_consecutive_poll_streaks(
    streaks,
    anomalous_ips,
    observed_ips,
    blocked_ips,
    hold_ips=None,
):
    """Update counters once per completed poll and return threshold candidates.

    Multiple anomalous flows from the same source in one poll count once.
    A completed poll that observes a src without a flood-sized alert resets
    that src. Overload / stale-dump / ML-cap rows in hold_ips are continued
    ANOMALY polls: they increment the streak (never freeze at 2/3).
    """
    anomalous = {str(ip) for ip in anomalous_ips}
    observed = {str(ip) for ip in observed_ips}
    blocked = {str(ip) for ip in blocked_ips}
    hold = {str(ip) for ip in (hold_ips or ())} - anomalous
    tracked = set(streaks) | observed
    incremented = []
    for ip_src in tracked:
        if ip_src in blocked:
            continue
        if ip_src in anomalous or ip_src in hold:
            streaks[ip_src] = int(streaks.get(ip_src, 0)) + 1
            incremented.append(ip_src)
        else:
            streaks[ip_src] = 0
    return incremented
