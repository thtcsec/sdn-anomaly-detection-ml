"""Pure mitigation policy helpers, independent of os-ken."""

from __future__ import annotations

# Three completed polls with a source-level alert → OpenFlow DROP.
DEFAULT_ALERT_THRESHOLD = 3
# DROP match priority (above L2/L3 forwarding entries at priority 1).
BLOCK_FLOW_PRIORITY = 1000


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
