"""3-poll streak and OpenFlow DROP priority — no os-ken import."""

from __future__ import annotations

from mitigation_policy import (
    BLOCK_COOKIE,
    BLOCK_FLOW_PRIORITY,
    DEFAULT_ALERT_THRESHOLD,
    MIN_FLOOD_DELTA_PACKETS,
    MIN_STALE_MICROFLOW_COUNT,
    PROTECTED_VICTIM_IPS,
    aggregate_ip_stats,
    decide_mitigation_cycle,
    drop_attack_type,
    first_sighting_packet_delta,
    is_flood_source,
    may_install_drop,
    select_hold_ips,
    select_streak_ips,
    should_send_flow_stats_request,
    update_consecutive_poll_streaks,
)


def test_priority_and_streak_constants():
    """Thesis/demo mitigation: 3 consecutive polls, DROP priority 1000."""
    assert DEFAULT_ALERT_THRESHOLD == 3
    assert BLOCK_FLOW_PRIORITY == 1000
    assert BLOCK_COOKIE == 0x53444E424C4F434B


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
    ) == set()


def test_incomplete_poll_increments_ongoing_streak():
    """Incomplete dump during an attack is not a miss: 2/3 → 3/3."""
    streaks = {"10.0.0.4": 2}
    hold = select_hold_ips(
        observed_ips=set(),
        flood_ips=set(),
        incomplete=True,
        tracked_streak_ips=streaks,
    )
    assert "10.0.0.4" in hold
    incremented = update_consecutive_poll_streaks(
        streaks, set(), set(), set(), hold_ips=hold,
    )
    assert incremented == ["10.0.0.4"]
    assert streaks["10.0.0.4"] == DEFAULT_ALERT_THRESHOLD


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


def test_stale_dump_hold_increments_to_block():
    """2/3 then overload/stale dump must reach 3/3 — freeze at 2/3 is forbidden."""
    streaks = {"10.0.0.4": 2}
    hold = select_hold_ips(
        observed_ips={"10.0.0.4"},
        flood_ips=set(),
        delta_packets_by_ip={"10.0.0.4": 0},
        flow_count_by_ip={"10.0.0.4": 61160},
        poll_delta_packets=0,
        tracked_streak_ips=streaks,
    )
    assert "10.0.0.4" in hold
    incremented = update_consecutive_poll_streaks(
        streaks, set(), {"10.0.0.4"}, set(), hold_ips=hold,
    )
    assert incremented == ["10.0.0.4"]
    assert streaks["10.0.0.4"] == DEFAULT_ALERT_THRESHOLD


def test_consecutive_stale_holds_never_freeze_at_two():
    """ANOMALY 1/3 then two stale HOLD+ polls still reach 3/3."""
    streaks = {"10.0.0.4": 1}
    for _ in range(2):
        hold = select_hold_ips(
            observed_ips={"10.0.0.4"},
            flood_ips=set(),
            delta_packets_by_ip={"10.0.0.4": 0},
            flow_count_by_ip={"10.0.0.4": 400},
            poll_delta_packets=0,
            tracked_streak_ips=streaks,
        )
        assert "10.0.0.4" in hold
        update_consecutive_poll_streaks(
            streaks, set(), {"10.0.0.4"}, set(), hold_ips=hold,
        )
    assert streaks["10.0.0.4"] == DEFAULT_ALERT_THRESHOLD


def test_true_miss_other_hosts_resets_streak():
    """Quiet / other hosts, no flood from 10.0.0.4 → reset, not HOLD."""
    streaks = {"10.0.0.4": 2}
    hold = select_hold_ips(
        observed_ips={"10.0.0.1", "10.0.0.2"},
        flood_ips=set(),
        delta_packets_by_ip={"10.0.0.1": 8, "10.0.0.2": 4},
        flow_count_by_ip={"10.0.0.1": 2, "10.0.0.2": 1},
        poll_delta_packets=12,
        tracked_streak_ips=streaks,
    )
    assert "10.0.0.4" not in hold
    update_consecutive_poll_streaks(
        streaks, set(), {"10.0.0.1", "10.0.0.2"}, set(), hold_ips=hold,
    )
    assert streaks["10.0.0.4"] == 0


def test_hold_never_includes_protected_victims():
    hold = select_hold_ips(
        observed_ips={"10.0.0.1", "10.0.0.4"},
        flood_ips=set(),
        delta_packets_by_ip={"10.0.0.1": 0, "10.0.0.4": 0},
        flow_count_by_ip={"10.0.0.1": 500, "10.0.0.4": 500},
        poll_delta_packets=0,
        tracked_streak_ips={"10.0.0.1": 2, "10.0.0.4": 2},
        incomplete=True,
    )
    assert "10.0.0.1" not in hold
    assert "10.0.0.4" in hold


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


def test_idle_startup_never_holds_or_blocks():
    """pps=0 all-NORMAL leftover table must not HOLD+ or reach 3/3."""
    streaks = {}
    observed = {"10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.1"}
    deltas = {ip: 0 for ip in observed}
    counts = {"10.0.0.4": 80, "10.0.0.5": 80, "10.0.0.6": 80, "10.0.0.1": 40}
    for _ in range(DEFAULT_ALERT_THRESHOLD):
        hold = select_hold_ips(
            observed_ips=observed,
            flood_ips=set(),
            delta_packets_by_ip=deltas,
            flow_count_by_ip=counts,
            poll_delta_packets=0,
            tracked_streak_ips=streaks,
            last_anomaly_flood_ips=set(),
        )
        assert hold == set()
        update_consecutive_poll_streaks(
            streaks, set(), observed, set(), hold_ips=hold,
        )
    assert streaks.get("10.0.0.4", 0) == 0
    assert streaks.get("10.0.0.5", 0) == 0
    assert streaks.get("10.0.0.6", 0) == 0


def test_hold_does_not_fire_on_normal_without_prior_anomaly():
    """Stale dump + many NORMAL flows must not HOLD+ any src from streak 0."""
    hold = select_hold_ips(
        observed_ips={"10.0.0.4", "10.0.0.5", "10.0.0.6"},
        flood_ips=set(),
        delta_packets_by_ip={"10.0.0.4": 0, "10.0.0.5": 0, "10.0.0.6": 0},
        flow_count_by_ip={"10.0.0.4": 100, "10.0.0.5": 80, "10.0.0.6": 60},
        poll_delta_packets=0,
        tracked_streak_ips={"10.0.0.4": 0, "10.0.0.5": 0, "10.0.0.6": 0},
    )
    assert hold == set()
    streaks = {"10.0.0.4": 0, "10.0.0.5": 0, "10.0.0.6": 0}
    update_consecutive_poll_streaks(
        streaks, set(), {"10.0.0.4", "10.0.0.5", "10.0.0.6"}, set(),
        hold_ips={"10.0.0.4", "10.0.0.5", "10.0.0.6"},
    )
    assert streaks["10.0.0.4"] == 0
    assert streaks["10.0.0.5"] == 0
    assert streaks["10.0.0.6"] == 0


def test_hold_increments_only_after_anomaly():
    """HOLD+ continues a flood streak; idle first polls do not start one."""
    streaks = {}
    ip = "10.0.0.4"
    idle = select_hold_ips(
        observed_ips={ip, "10.0.0.5", "10.0.0.6"},
        flood_ips=set(),
        delta_packets_by_ip={ip: 0, "10.0.0.5": 0, "10.0.0.6": 0},
        flow_count_by_ip={ip: 80, "10.0.0.5": 80, "10.0.0.6": 80},
        poll_delta_packets=0,
        tracked_streak_ips=streaks,
        last_anomaly_flood_ips=set(),
    )
    assert idle == set()
    update_consecutive_poll_streaks(streaks, set(), {ip}, set(), hold_ips=idle)
    assert streaks.get(ip, 0) == 0

    update_consecutive_poll_streaks(streaks, {ip}, {ip}, set())
    assert streaks[ip] == 1
    last_flood = {ip}
    others = {"10.0.0.5", "10.0.0.6"}
    for _ in range(2):
        hold = select_hold_ips(
            observed_ips={ip, *others},
            flood_ips=set(),
            delta_packets_by_ip={ip: 0, "10.0.0.5": 2, "10.0.0.6": 1},
            flow_count_by_ip={ip: 400, "10.0.0.5": 2, "10.0.0.6": 1},
            poll_delta_packets=0,
            tracked_streak_ips=streaks,
            last_anomaly_flood_ips=last_flood,
        )
        assert hold == {ip}
        update_consecutive_poll_streaks(
            streaks, set(), {ip, *others}, set(), hold_ips=hold,
        )
    assert streaks[ip] == DEFAULT_ALERT_THRESHOLD
    assert streaks.get("10.0.0.5", 0) == 0
    assert streaks.get("10.0.0.6", 0) == 0


def test_true_miss_resets_even_after_hold_eligible_volume():
    """Quiet poll without 10.0.0.4 flood volume → reset, not HOLD+."""
    streaks = {"10.0.0.4": 2}
    hold = select_hold_ips(
        observed_ips={"10.0.0.1", "10.0.0.2", "10.0.0.5"},
        flood_ips=set(),
        delta_packets_by_ip={"10.0.0.1": 4, "10.0.0.2": 3, "10.0.0.5": 2},
        flow_count_by_ip={"10.0.0.1": 1, "10.0.0.2": 1, "10.0.0.5": 1},
        poll_delta_packets=9,
        tracked_streak_ips=streaks,
        last_anomaly_flood_ips={"10.0.0.4"},
    )
    assert "10.0.0.4" not in hold
    update_consecutive_poll_streaks(
        streaks, set(), {"10.0.0.1", "10.0.0.2", "10.0.0.5"}, set(), hold_ips=hold,
    )
    assert streaks["10.0.0.4"] == 0


def test_protected_victims_never_drop():
    for ip in PROTECTED_VICTIM_IPS:
        assert not may_install_drop(ip, "ANOMALY")
        assert not may_install_drop(ip, "DDOS")
        hold = select_hold_ips(
            observed_ips={ip, "10.0.0.4"},
            flood_ips=set(),
            delta_packets_by_ip={ip: 0, "10.0.0.4": 0},
            flow_count_by_ip={ip: 500, "10.0.0.4": 500},
            poll_delta_packets=0,
            tracked_streak_ips={ip: 2, "10.0.0.4": 2},
            last_anomaly_flood_ips={ip, "10.0.0.4"},
        )
        assert ip not in hold
    assert not may_install_drop("10.0.0.4", "NORMAL")
    assert not may_install_drop("10.0.0.4", "NORMAL/NORMAL")
    assert may_install_drop("10.0.0.4", "ANOMALY")
    assert may_install_drop("10.0.0.4", "DDOS")
    assert drop_attack_type({"NORMAL"}, last_alert_label="ANOMALY", is_hold=True) == "ANOMALY"
    assert drop_attack_type({"NORMAL"}, is_hold=False) == "NORMAL"


def test_skipped_ml_normal_idle_does_not_streak():
    """ML cap leftover NORMAL flows are not a silent flood."""
    chosen = select_streak_ips(
        set(),
        {"10.0.0.4": 0, "10.0.0.5": 0},
        skipped_ml_ips={"10.0.0.4", "10.0.0.5"},
        flow_count_by_ip={"10.0.0.4": 100, "10.0.0.5": 80},
        normal_ips={"10.0.0.4", "10.0.0.5"},
    )
    assert chosen == set()


def test_unlabeled_skip_without_this_poll_packets_does_not_start():
    """Leftover 60k 5-tuples + ML skip + delta=0 must not open 0→1."""
    assert MIN_STALE_MICROFLOW_COUNT == 256
    chosen = select_streak_ips(
        set(),
        {"10.0.0.4": 0, "10.0.0.5": 0, "10.0.0.6": 0},
        skipped_ml_ips={"10.0.0.4", "10.0.0.5", "10.0.0.6"},
        flow_count_by_ip={"10.0.0.4": 80, "10.0.0.5": 80, "10.0.0.6": 80},
    )
    assert chosen == set()
    chosen = select_streak_ips(
        set(),
        {"10.0.0.4": 400},
        skipped_ml_ips={"10.0.0.4"},
        flow_count_by_ip={"10.0.0.4": 400},
    )
    assert chosen == {"10.0.0.4"}


def test_first_sighting_ignores_old_leftover_duration():
    assert first_sighting_packet_delta(1, duration_sec=0) == 1
    assert first_sighting_packet_delta(80, duration_sec=2, poll_interval=5.0) == 80
    assert first_sighting_packet_delta(80, duration_sec=20, poll_interval=5.0) == 0
    assert first_sighting_packet_delta(1, duration_sec=60, poll_interval=5.0) == 0


def test_skip_overlapping_flow_stats_request():
    assert should_send_flow_stats_request(set()) is True
    assert should_send_flow_stats_request({1, 2}) is False
    assert should_send_flow_stats_request(None) is True


def _run_cycle(**kwargs):
    defaults = dict(
        skipped_ml_ips=set(),
        incomplete=False,
        blocked_ips=set(),
        last_anomaly_flood_ips=set(),
        last_alert_label={},
        alert_threshold=DEFAULT_ALERT_THRESHOLD,
        mitigation_enabled=True,
    )
    defaults.update(kwargs)
    return decide_mitigation_cycle(**defaults)


def test_idle_three_polls_never_hold_or_drop():
    """Idle leftover NORMAL on .4/.5/.6: blocked empty, no HOLD+, no DROP."""
    streaks = {}
    last_flood = set()
    last_label = {}
    observed = {"10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.1"}
    labels = {ip: {"NORMAL"} for ip in observed}
    deltas = {ip: 0 for ip in observed}
    counts = {"10.0.0.4": 80, "10.0.0.5": 80, "10.0.0.6": 80, "10.0.0.1": 40}
    for _ in range(DEFAULT_ALERT_THRESHOLD):
        d = _run_cycle(
            anomalous_ips=set(),
            observed_ips=observed,
            labels_by_ip=labels,
            delta_packets_by_ip=deltas,
            flow_count_by_ip=counts,
            skipped_ml_ips={"10.0.0.4", "10.0.0.5", "10.0.0.6"},
            poll_delta_packets=0,
            streaks=streaks,
            last_anomaly_flood_ips=last_flood,
            last_alert_label=last_label,
        )
        last_flood = d["last_anomaly_flood_ips"]
        assert d["hold_ips"] == set()
        assert d["flood_ips"] == set()
        assert d["drops"] == []
    assert all(int(streaks.get(ip, 0) or 0) == 0 for ip in observed)


def test_h4_anomaly_three_polls_drops_only_h4():
    """Attack h4: 1/3 → 2/3 → 3/3 DROP only 10.0.0.4 with ANOMALY."""
    streaks = {}
    last_flood = set()
    last_label = {}
    observed = {"10.0.0.1", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
    labels = {
        "10.0.0.4": {"ANOMALY"},
        "10.0.0.1": {"NORMAL"},
        "10.0.0.5": {"NORMAL"},
        "10.0.0.6": {"NORMAL"},
    }
    deltas = {"10.0.0.4": 400, "10.0.0.1": 8, "10.0.0.5": 4, "10.0.0.6": 3}
    counts = {"10.0.0.4": 400, "10.0.0.1": 2, "10.0.0.5": 2, "10.0.0.6": 1}
    drops = []
    for step in range(DEFAULT_ALERT_THRESHOLD):
        d = _run_cycle(
            anomalous_ips={"10.0.0.4"},
            observed_ips=observed,
            labels_by_ip=labels,
            delta_packets_by_ip=deltas,
            flow_count_by_ip=counts,
            poll_delta_packets=415,
            streaks=streaks,
            last_anomaly_flood_ips=last_flood,
            last_alert_label=last_label,
        )
        last_flood = d["last_anomaly_flood_ips"]
        assert d["hold_ips"] == set()
        assert streaks["10.0.0.4"] == step + 1
        assert streaks.get("10.0.0.5", 0) == 0
        assert streaks.get("10.0.0.6", 0) == 0
        drops.extend(d["drops"])
    assert drops == [("10.0.0.4", "ANOMALY")]
    assert all(ip == "10.0.0.4" for ip, _ in drops)
    assert all(label != "NORMAL" for _, label in drops)


def test_hold_after_anomaly_reaches_drop_not_normal():
    """ANOMALY 1/3 then two stale HOLD+ polls → DROP ANOMALY, never Attack:NORMAL."""
    streaks = {}
    last_flood = set()
    last_label = {}
    d1 = _run_cycle(
        anomalous_ips={"10.0.0.4"},
        observed_ips={"10.0.0.4", "10.0.0.5"},
        labels_by_ip={"10.0.0.4": {"ANOMALY"}, "10.0.0.5": {"NORMAL"}},
        delta_packets_by_ip={"10.0.0.4": 400, "10.0.0.5": 2},
        flow_count_by_ip={"10.0.0.4": 400, "10.0.0.5": 2},
        poll_delta_packets=402,
        streaks=streaks,
        last_anomaly_flood_ips=last_flood,
        last_alert_label=last_label,
    )
    last_flood = d1["last_anomaly_flood_ips"]
    assert streaks["10.0.0.4"] == 1
    assert d1["drops"] == []
    for _ in range(2):
        d = _run_cycle(
            anomalous_ips=set(),
            observed_ips={"10.0.0.4", "10.0.0.5"},
            labels_by_ip={"10.0.0.4": {"NORMAL"}, "10.0.0.5": {"NORMAL"}},
            delta_packets_by_ip={"10.0.0.4": 0, "10.0.0.5": 2},
            flow_count_by_ip={"10.0.0.4": 400, "10.0.0.5": 2},
            skipped_ml_ips={"10.0.0.4"},
            poll_delta_packets=0,
            streaks=streaks,
            last_anomaly_flood_ips=last_flood,
            last_alert_label=last_label,
        )
        last_flood = d["last_anomaly_flood_ips"]
        assert "10.0.0.4" in d["hold_ips"]
        assert "10.0.0.5" not in d["hold_ips"]
        last_d = d
    assert streaks["10.0.0.4"] == DEFAULT_ALERT_THRESHOLD
    assert last_d["drops"] == [("10.0.0.4", "ANOMALY")]
    assert last_d["drops"][0][1] != "NORMAL"


def test_decide_never_drops_victims_or_normal_label():
    streaks = {"10.0.0.1": 2, "10.0.0.4": 2}
    last_label = {"10.0.0.1": "ANOMALY", "10.0.0.4": "NORMAL"}
    d = _run_cycle(
        anomalous_ips={"10.0.0.1", "10.0.0.4"},
        observed_ips={"10.0.0.1", "10.0.0.4"},
        labels_by_ip={"10.0.0.1": {"ANOMALY"}, "10.0.0.4": {"NORMAL"}},
        delta_packets_by_ip={"10.0.0.1": 5000, "10.0.0.4": 5000},
        flow_count_by_ip={"10.0.0.1": 500, "10.0.0.4": 500},
        poll_delta_packets=10000,
        streaks=streaks,
        last_anomaly_flood_ips={"10.0.0.1", "10.0.0.4"},
        last_alert_label=last_label,
    )
    drop_ips = {ip for ip, _ in d["drops"]}
    assert "10.0.0.1" not in drop_ips
    assert "10.0.0.2" not in drop_ips
    assert "10.0.0.3" not in drop_ips
    for _ip, label in d["drops"]:
        assert "NORMAL" not in label
        assert may_install_drop(_ip, label)


def test_true_miss_resets_then_no_hold():
    streaks = {"10.0.0.4": 2}
    last_label = {"10.0.0.4": "ANOMALY"}
    d = _run_cycle(
        anomalous_ips=set(),
        observed_ips={"10.0.0.1", "10.0.0.5"},
        labels_by_ip={"10.0.0.1": {"NORMAL"}, "10.0.0.5": {"NORMAL"}},
        delta_packets_by_ip={"10.0.0.1": 4, "10.0.0.5": 2},
        flow_count_by_ip={"10.0.0.1": 1, "10.0.0.5": 1},
        poll_delta_packets=6,
        streaks=streaks,
        last_anomaly_flood_ips={"10.0.0.4"},
        last_alert_label=last_label,
    )
    assert "10.0.0.4" not in d["hold_ips"]
    assert streaks["10.0.0.4"] == 0
    assert d["drops"] == []
