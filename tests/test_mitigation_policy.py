"""3-poll streak and OpenFlow DROP priority — no os-ken import."""

from __future__ import annotations

from mitigation_policy import (
    BLOCK_FLOW_PRIORITY,
    DEFAULT_ALERT_THRESHOLD,
    MIN_FLOOD_DELTA_PACKETS,
    PROTECTED_VICTIM_IPS,
    is_flood_source,
    select_streak_ips,
    update_consecutive_poll_streaks,
)


def test_priority_and_streak_constants():
    """Thesis/demo mitigation: 3 consecutive polls, DROP priority 1000."""
    assert DEFAULT_ALERT_THRESHOLD == 3
    assert BLOCK_FLOW_PRIORITY == 1000


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
