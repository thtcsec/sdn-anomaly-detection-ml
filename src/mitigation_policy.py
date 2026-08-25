"""Pure mitigation policy helpers, independent of os-ken."""

from __future__ import annotations

# Three completed polls with a source-level alert → OpenFlow DROP.
DEFAULT_ALERT_THRESHOLD = 3
# DROP match priority (above L2/L3 forwarding entries at priority 1).
BLOCK_FLOW_PRIORITY = 1000

# Demo/thesis fabric: h1–h3 are servers/victims — never auto-DROP them.
PROTECTED_VICTIM_IPS = frozenset({"10.0.0.1", "10.0.0.2", "10.0.0.3"})
# Written on OFPFlowMod cookie; ASCII-ish "SDNBLOCK". Exact-match delete only:
#   ovs-ofctl -O OpenFlow13 del-flows s1 cookie=0x53444e424c4f434b/-1
#   ovs-ofctl -O OpenFlow13 del-flows s2 cookie=0x53444e424c4f434b/-1
# Never `del-flows s1` bare — that wipes table-miss / L2 forwarding.
BLOCK_COOKIE = 0x53444E424C4F434B
DROP_ALERT_LABELS = frozenset({"DDOS", "PORTSCAN", "ANOMALY"})
# RF may label idle ICMP ANOMALY; only streak sources with a flood-sized packet delta this poll (not LOSO).
MIN_FLOOD_DELTA_PACKETS = 30
# Cap RF inferences per completed OpenFlow poll so a 5s cycle can finish
# during SYN-flood (tens of thousands of microflows). Sampling is a realtime
# budget, not a change to offline LOSO.
MAX_ML_FLOWS_PER_POLL = 256
# Overlapping SYN dumps report packet_delta=0 while the table still holds
# thousands of 5-tuples. Modest leftover ARP/ICMP tables (tens of flows) must
# not count as that. Must stay >= MAX_ML_FLOWS_PER_POLL so idle leftovers
# below the ML cap cannot start a streak via flow-count alone.
MIN_STALE_MICROFLOW_COUNT = MAX_ML_FLOWS_PER_POLL


def is_flood_source(ip_src, delta_packets, protected=None, min_delta=None):
    """True if this src is an auto-block candidate (flood volume, not a victim host)."""
    protected = PROTECTED_VICTIM_IPS if protected is None else protected
    min_delta = MIN_FLOOD_DELTA_PACKETS if min_delta is None else min_delta
    if str(ip_src) in protected:
        return False
    return int(delta_packets or 0) >= int(min_delta)


def first_sighting_packet_delta(packet_count, duration_sec, poll_interval=5.0):
    """Lifetime packet_count is this-cycle delta only for young 5-tuples.

    New SYN microflows live inside one poll window. Leftover installs from
    before this controller (duration already > poll_interval) must not look
    like a flood on the first dump after restart.
    """
    pkts = int(packet_count or 0)
    if pkts <= 0:
        return 0
    if float(duration_sec or 0) > float(poll_interval) + 1.0:
        return 0
    return pkts


def should_send_flow_stats_request(inflight_xids):
    """False while a dump is still in flight — never overlap OFPFlowStatsRequest."""
    return not bool(inflight_xids)


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
    normal_ips=None,
):
    """ANOMALY sources that may increment the 3-poll DROP streak this cycle.

    Volume is per source IP across the whole dump: many 1-packet SYN microflows
    still count when their summed packet_delta is flood-sized (≥30), even if
    every individual 5-tuple is below that. A src also qualifies if some of
    its flows were skipped by the per-poll ML cap *and this poll still saw
    flood-sized packet_delta* — leftover 5-tuple count alone is not a start.
    Never if this poll already classified that src NORMAL.
    """
    deltas = delta_packets_by_ip or {}
    counts = flow_count_by_ip or {}
    anomalous = {str(ip) for ip in (anomalous_ips or ())}
    normal = {str(ip) for ip in (normal_ips or ())}
    min_delta = MIN_FLOOD_DELTA_PACKETS if min_delta is None else min_delta
    chosen = {
        ip
        for ip in anomalous
        if is_flood_source(
            ip,
            _src_flood_volume(ip, deltas, counts),
            protected,
            min_delta,
        )
    }
    for ip in skipped_ml_ips or ():
        ip = str(ip)
        if ip in chosen:
            continue
        if ip in normal and ip not in anomalous:
            continue
        # Unlabeled ML-cap skip: this-poll packets only. A leftover SYN table
        # with packet_delta=0 must not open 0→1; HOLD+ continues an old streak.
        this_poll = int(deltas.get(ip, 0) or 0)
        if this_poll < int(min_delta):
            continue
        if is_flood_source(ip, this_poll, protected, min_delta):
            chosen.add(ip)
    return chosen


def _src_flood_volume(ip, deltas, counts):
    """Per-IP flood size: this-poll packet_delta, else a huge stale SYN table.

    hping random-sport SYNs are 1-packet 5-tuples. Overlapping dumps often report
    packet_delta=0 while the table still holds tens of thousands of flows —
    count those as volume. Modest leftover ARP/ICMP tables must not qualify.
    """
    n_delta = int(deltas.get(ip, 0) or 0)
    n_flows = int(counts.get(ip, 0) or 0)
    if n_delta >= MIN_FLOOD_DELTA_PACKETS:
        return n_delta
    if n_flows >= MIN_STALE_MICROFLOW_COUNT:
        return n_flows
    return n_delta


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
    last_anomaly_flood_ips=None,
):
    """Continue an in-progress flood streak across one stale/overload dump.

    HOLD+ is not a miss, but it must never *start* a streak. Required:
    (a) that src already has a consecutive-poll streak from a prior flood
        ANOMALY (optionally intersected with last_anomaly_flood_ips);
    (b) this dump is stale/overload (incomplete, overlapping FlowStats /
        packet_delta=0, or ML-cap skip);
    (c) that src still has flood-sized volume — not idle ARP/ping, not a
        pps=0 all-NORMAL table of leftover 5-tuples.

    Idle / first polls / empty delta / all NORMAL → empty set.
    Victim hosts h1–h3 are never held. Freezing a real flood at 2/3 is
    still forbidden.
    """
    protected = PROTECTED_VICTIM_IPS
    observed = {str(ip) for ip in (observed_ips or ())} - protected
    flood = {str(ip) for ip in (flood_ips or ())}
    skipped = {str(ip) for ip in (skipped_ml_ips or ())}
    deltas = delta_packets_by_ip or {}
    counts = flow_count_by_ip or {}
    ongoing = _positive_streak_ips(tracked_streak_ips) - protected
    if last_anomaly_flood_ips is None:
        eligible = set(ongoing)
    else:
        eligible = ongoing & ({str(ip) for ip in last_anomaly_flood_ips} - protected)
    eligible -= flood

    # Dump did not finish during an in-progress flood: not a miss.
    if incomplete:
        return eligible

    pps_dead = int(poll_delta_packets or 0) <= 0
    hold = set()
    for ip in eligible:
        n_flows = int(counts.get(ip, 0) or 0)
        n_delta = int(deltas.get(ip, 0) or 0)
        if _src_flood_volume(ip, deltas, counts) < MIN_FLOOD_DELTA_PACKETS:
            continue
        stale = (
            ip in skipped
            or (n_flows >= MIN_STALE_MICROFLOW_COUNT and n_delta < MIN_FLOOD_DELTA_PACKETS)
            or (pps_dead and n_flows >= MIN_STALE_MICROFLOW_COUNT)
        )
        if stale and (ip in observed or ip in skipped):
            hold.add(ip)
    return hold


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


def parse_attack_labels(attack_type):
    """Split a DROP/log label string into uppercase tokens."""
    raw = str(attack_type or "").replace("|", "/")
    return {part.strip().upper() for part in raw.split("/") if part.strip()}


def drop_attack_type(current_labels, last_alert_label=None, is_hold=False):
    """Label written on DROP. HOLD+ reuses the last flood class, never NORMAL."""
    current = {str(x).upper() for x in (current_labels or ()) if str(x).strip()}
    alerts = sorted(current & DROP_ALERT_LABELS)
    if alerts:
        return "/".join(alerts)
    if is_hold:
        prev = parse_attack_labels(last_alert_label) & DROP_ALERT_LABELS
        if prev:
            return "/".join(sorted(prev))
        return "ANOMALY"
    return "NORMAL"


def may_install_drop(ip, attack_type, protected=None):
    """OpenFlow DROP is never installed for victims or NORMAL-only labels."""
    protected = PROTECTED_VICTIM_IPS if protected is None else protected
    if str(ip) in protected:
        return False
    labels = parse_attack_labels(attack_type)
    if not labels or labels <= {"NORMAL"}:
        return False
    return bool(labels & DROP_ALERT_LABELS)


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
    that src. HOLD+ rows increment only if that src already has a streak
    (prior flood ANOMALY); they never start 0→1 on NORMAL/idle.
    """
    anomalous = {str(ip) for ip in anomalous_ips}
    observed = {str(ip) for ip in observed_ips}
    blocked = {str(ip) for ip in blocked_ips}
    hold = {str(ip) for ip in (hold_ips or ())} - anomalous
    tracked = set(streaks) | observed | hold
    incremented = []
    for ip_src in tracked:
        if ip_src in blocked:
            continue
        prior = int(streaks.get(ip_src, 0) or 0)
        if ip_src in anomalous:
            streaks[ip_src] = prior + 1
            incremented.append(ip_src)
        elif ip_src in hold and prior > 0:
            streaks[ip_src] = prior + 1
            incremented.append(ip_src)
        else:
            streaks[ip_src] = 0
    return incremented


def decide_mitigation_cycle(
    *,
    anomalous_ips,
    observed_ips,
    labels_by_ip,
    delta_packets_by_ip,
    flow_count_by_ip,
    skipped_ml_ips,
    incomplete,
    poll_delta_packets,
    streaks,
    blocked_ips,
    last_anomaly_flood_ips,
    last_alert_label,
    alert_threshold=DEFAULT_ALERT_THRESHOLD,
    mitigation_enabled=True,
):
    """One completed-poll decision: flood / HOLD+ / reset / DROP candidates.

    Mutates ``streaks`` and ``last_alert_label``. Does not install OpenFlow.
    DROP candidates never include victims or NORMAL-only labels.
    """
    labels_by_ip = labels_by_ip or {}
    last_alert_label = last_alert_label if last_alert_label is not None else {}
    last_flood = set(last_anomaly_flood_ips or ())
    blocked = set(blocked_ips or ())
    normal_ips = {
        str(ip)
        for ip, labs in labels_by_ip.items()
        if labs and not ({str(x) for x in labs} & DROP_ALERT_LABELS)
    }
    flood_ips = select_streak_ips(
        anomalous_ips,
        delta_packets_by_ip,
        skipped_ml_ips=skipped_ml_ips,
        flow_count_by_ip=flow_count_by_ip,
        normal_ips=normal_ips,
    )
    hold_ips = select_hold_ips(
        observed_ips,
        flood_ips,
        delta_packets_by_ip=delta_packets_by_ip,
        flow_count_by_ip=flow_count_by_ip,
        skipped_ml_ips=skipped_ml_ips,
        incomplete=incomplete,
        poll_delta_packets=poll_delta_packets,
        tracked_streak_ips=streaks,
        last_anomaly_flood_ips=last_flood,
    )
    incremented = update_consecutive_poll_streaks(
        streaks,
        flood_ips,
        observed_ips,
        blocked,
        hold_ips=hold_ips,
    )
    for ip_src in flood_ips:
        labs = {str(x) for x in (labels_by_ip.get(ip_src) or ())}
        alerts = labs & DROP_ALERT_LABELS
        if alerts:
            last_alert_label[ip_src] = "/".join(sorted(alerts))
        elif ip_src not in last_alert_label:
            last_alert_label[ip_src] = "ANOMALY"
    drops = []
    if mitigation_enabled:
        for ip_src in incremented:
            if int(streaks.get(ip_src, 0) or 0) < int(alert_threshold):
                continue
            is_hold = ip_src in hold_ips and ip_src not in flood_ips
            if ip_src not in flood_ips and not is_hold:
                continue
            attack_type = drop_attack_type(
                labels_by_ip.get(ip_src),
                last_alert_label.get(ip_src),
                is_hold=is_hold,
            )
            if may_install_drop(ip_src, attack_type):
                drops.append((str(ip_src), attack_type))
    live = {
        ip for ip, n in streaks.items() if int(n or 0) > 0
    } - blocked
    new_last_flood = (set(flood_ips) | set(hold_ips) | last_flood) & live
    for ip in list(last_alert_label):
        if ip not in live and ip not in blocked:
            last_alert_label.pop(ip, None)
    return {
        "flood_ips": flood_ips,
        "hold_ips": hold_ips,
        "incremented": incremented,
        "drops": drops,
        "last_anomaly_flood_ips": new_last_flood,
        "last_alert_label": last_alert_label,
    }
