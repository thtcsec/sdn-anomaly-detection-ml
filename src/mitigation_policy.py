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


def is_flood_source(ip_src, delta_packets, protected=None, min_delta=None):
    """True if this src is an auto-block candidate (flood volume, not a victim host)."""
    protected = PROTECTED_VICTIM_IPS if protected is None else protected
    min_delta = MIN_FLOOD_DELTA_PACKETS if min_delta is None else min_delta
    if str(ip_src) in protected:
        return False
    return int(delta_packets or 0) >= int(min_delta)


def select_streak_ips(anomalous_ips, delta_packets_by_ip, protected=None, min_delta=None):
    """ANOMALY sources that may increment the 3-poll DROP streak this cycle."""
    deltas = delta_packets_by_ip or {}
    return {
        str(ip)
        for ip in anomalous_ips
        if is_flood_source(ip, deltas.get(str(ip), 0), protected, min_delta)
    }


def update_consecutive_poll_streaks(streaks, anomalous_ips, observed_ips, blocked_ips):
    """Update counters once per completed poll and return threshold candidates.

    Multiple anomalous flows from the same source in one poll count once.
    Any completed poll without an anomalous observation resets the streak.
    """
    anomalous = {str(ip) for ip in anomalous_ips}
    observed = {str(ip) for ip in observed_ips}
    blocked = {str(ip) for ip in blocked_ips}
    tracked = set(streaks) | observed
    incremented = []
    for ip_src in tracked:
        if ip_src not in anomalous:
            streaks[ip_src] = 0
        elif ip_src not in blocked:
            streaks[ip_src] = int(streaks.get(ip_src, 0)) + 1
            incremented.append(ip_src)
    return incremented
