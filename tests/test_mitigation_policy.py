"""3-poll streak and OpenFlow DROP priority — no os-ken import."""

from __future__ import annotations

from mitigation_policy import (
    BLOCK_FLOW_PRIORITY,
    DEFAULT_ALERT_THRESHOLD,
    MIN_FLOOD_DELTA_PACKETS,
    PROTECTED_VICTIM_IPS,
    aggregate_ip_stats,
    is_flood_source,
    select_hold_ips,
    select_streak_ips,
    update_consecutive_poll_streaks,
)


def test_priority_and_streak_constants():
    """Thesis/demo mitigation: 3 consecutive polls, DROP priority 1000."""
    assert DEFAULT_ALERT_THRESHOLD == 3
    assert BLOCK_FLOW_PRIORITY == 1000


def test_ml_cap_constant_is_realtime_budget():
    """Per-poll inference cap — sampling is not a change to offline LOSO."""
    from mitigation_policy import MAX_ML_FLOWS_PER_POLL

    assert MAX_ML_FLOWS_PER_POLL == 256
    assert 128 <= MAX_ML_FLOWS_PER_POLL <= 256


def test_three_poll_streak_reaches_block_threshold():
    streaks = {}
    ip = "10.0.0.4"
    for _ in range(DEFAULT_ALERT_THRESHOLD):
        incremented = update_consecutive_poll_streaks(
            streaks, {ip}, {ip}, set(),
        )
        assert incremented == [ip]
    assert streaks[ip] == DEFAULT_ALERT_THRESHOLD


def test_many_flows_in_one_poll_count_once():
    streaks = {"10.0.0.4": 0}
    update_consecutive_poll_streaks(
        streaks,
        {"10.0.0.4", "10.0.0.4"},
        {"10.0.0.4"},
        set(),
    )
    assert streaks["10.0.0.4"] == 1


def test_benign_poll_resets_before_threshold():
    streaks = {"10.0.0.4": 2}
    update_consecutive_poll_streaks(streaks, set(), {"10.0.0.4"}, set())
    assert streaks["10.0.0.4"] == 0


def test_never_auto_block_victim_hosts():
    assert PROTECTED_VICTIM_IPS == frozenset({"10.0.0.1", "10.0.0.2", "10.0.0.3"})
    assert not is_flood_source("10.0.0.1", 10_000)
    assert not is_flood_source("10.0.0.2", 10_000)
    assert not is_flood_source("10.0.0.3", 10_000)


def test_icmp_ping_volume_does_not_streak():
    assert MIN_FLOOD_DELTA_PACKETS == 30
    assert not is_flood_source("10.0.0.6", 5)
    assert not is_flood_source("10.0.0.4", 29)
    assert is_flood_source("10.0.0.4", 30)


def test_select_streak_ips_h4_flood_only():
    chosen = select_streak_ips(
        {"10.0.0.1", "10.0.0.4", "10.0.0.5", "10.0.0.6"},
        {
            "10.0.0.1": 500,
            "10.0.0.4": 400,
            "10.0.0.5": 4,
            "10.0.0.6": 8,
        },
    )
    assert chosen == {"10.0.0.4"}


def test_select_ml_flows_prefers_high_delta_and_caps():
    from mitigation_policy import MAX_ML_FLOWS_PER_POLL, select_ml_flows

    flows = [
        {"ip_src": "10.0.0.5", "packet_delta": 1, "packet_count": 1},
        {"ip_src": "10.0.0.4", "packet_delta": 80, "packet_count": 80},
        {"ip_src": "10.0.0.6", "packet_delta": 2, "packet_count": 2},
    ]
    assert select_ml_flows(flows, max_n=1) == [1]
    many = [
        {"ip_src": "10.0.0.4", "packet_delta": 1, "packet_count": 1}
        for _ in range(1000)
    ]
    picked = select_ml_flows(many)
    assert len(picked) == MAX_ML_FLOWS_PER_POLL


def test_skipped_ml_flood_delta_still_streaks():
    """Unscored SYN microflows can still increment streak via flood-sized delta."""
    chosen = select_streak_ips(
        set(),
        {"10.0.0.4": 400, "10.0.0.1": 500},
        skipped_ml_ips={"10.0.0.4", "10.0.0.1"},
    )
    assert chosen == {"10.0.0.4"}
    assert select_streak_ips(set(), {"10.0.0.4": 400}) == set()


def test_aggregate_ip_stats_sums_microflow_deltas():
    flows = [{"ip_src": "10.0.0.4", "packet_delta": 1} for _ in range(40)]
    flows.append({"ip_src": "10.0.0.6", "packet_delta": 2})
    deltas, counts = aggregate_ip_stats(flows)
    assert deltas["10.0.0.4"] == 40
    assert counts["10.0.0.4"] == 40
    assert deltas["10.0.0.6"] == 2
    assert not is_flood_source("10.0.0.4", 1)
    assert select_streak_ips({"10.0.0.4"}, deltas, flow_count_by_ip=counts) == {"10.0.0.4"}


def test_microflow_count_is_src_volume_when_delta_lost():
    """Overlapping dump: 61k SYN 5-tuples, packet_delta=0, still flood-sized at the IP."""
    chosen = select_streak_ips(
        {"10.0.0.4"},
        {"10.0.0.4": 0},
        skipped_ml_ips={"10.0.0.4"},
        flow_count_by_ip={"10.0.0.4": 61160},
    )
    assert chosen == {"10.0.0.4"}
    assert select_streak_ips(
        set(),
        {"10.0.0.4": 0},
        skipped_ml_ips={"10.0.0.4"},
        flow_count_by_ip={"10.0.0.4": 61160},
    ) == {"10.0.0.4"}


def test_incomplete_poll_holds_streak_without_counting():
    streaks = {"10.0.0.4": 2}
    hold = select_hold_ips(
        observed_ips=set(),
        flood_ips=set(),
        incomplete=True,
        tracked_streak_ips=streaks,
    )
    assert "10.0.0.4" in hold
    update_consecutive_poll_streaks(streaks, set(), set(), set(), hold_ips=hold)
    assert streaks["10.0.0.4"] == 2


def test_benign_low_volume_poll_still_resets():
    streaks = {"10.0.0.4": 2}
    hold = select_hold_ips(
        observed_ips={"10.0.0.4"},
        flood_ips=set(),
        delta_packets_by_ip={"10.0.0.4": 4},
        flow_count_by_ip={"10.0.0.4": 1},
        poll_delta_packets=4,
    )
    assert hold == set()
    update_consecutive_poll_streaks(
        streaks, set(), {"10.0.0.4"}, set(), hold_ips=hold,
    )
    assert streaks["10.0.0.4"] == 0


def test_hold_does_not_count_toward_threshold():
    """Overload miss keeps 2/3; the third increment still requires a real flood poll."""
    streaks = {"10.0.0.4": 2}
    hold = {"10.0.0.4"}
    update_consecutive_poll_streaks(
        streaks, set(), {"10.0.0.4"}, set(), hold_ips=hold,
    )
    update_consecutive_poll_streaks(
        streaks, set(), {"10.0.0.4"}, set(), hold_ips=hold,
    )
    assert streaks["10.0.0.4"] == 2
    update_consecutive_poll_streaks(
        streaks, {"10.0.0.4"}, {"10.0.0.4"}, set(),
    )
    assert streaks["10.0.0.4"] == DEFAULT_ALERT_THRESHOLD


def test_zero_pps_microflow_dump_still_reaches_three():
    """Live 1→2, then a silent 60k SYN table (pps=0) still counts as src volume → 3/3."""
    streaks = {}
    ip = "10.0.0.4"
    update_consecutive_poll_streaks(streaks, {ip}, {ip}, set())
    update_consecutive_poll_streaks(streaks, {ip}, {ip}, set())
    assert streaks[ip] == 2
    silent = select_streak_ips(
        {ip},
        {ip: 0},
        skipped_ml_ips={ip},
        flow_count_by_ip={ip: 61160},
    )
    update_consecutive_poll_streaks(streaks, silent, {ip}, set())
    assert streaks[ip] == DEFAULT_ALERT_THRESHOLD
    assert DEFAULT_ALERT_THRESHOLD == 3
