"""3-poll streak and OpenFlow DROP priority — no os-ken import."""

from __future__ import annotations

from mitigation_policy import (
    BLOCK_FLOW_PRIORITY,
    DEFAULT_ALERT_THRESHOLD,
    update_consecutive_poll_streaks,
)


def test_priority_and_streak_constants():
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
