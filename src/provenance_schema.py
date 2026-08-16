"""
Shared provenance constants for independent Mininet lab runs.

Legacy rows (historical flow_stats.csv) MUST use unknown/legacy markers —
do not invent run_id for old data.
"""

from __future__ import annotations

# Core ML features (must stay stable for model training)
FEATURE_COLS = [
    'ip_proto',
    'tp_src',
    'tp_dst',
    'packet_count',
    'byte_count',
    'duration_sec',
    'packet_count_per_sec',
    'byte_count_per_sec',
    'packet_size_avg',
    'flow_duration',
]

# Existing columns in flow_stats.csv today
BASE_COLS = [
    'timestamp',
    'datapath_id',
    'flow_id',
    'ip_src',
    'ip_dst',
    'ip_proto',
    'tp_src',
    'tp_dst',
    'packet_count',
    'byte_count',
    'duration_sec',
    'duration_nsec',
    'packet_count_per_sec',
    'byte_count_per_sec',
    'packet_size_avg',
    'flow_duration',
    'label',
    'is_synthetic',
    'source',
]

# New session provenance (backward-compatible extras)
RUN_META_COLS = [
    'run_id',
    'scenario_id',
    'capture_session_id',
    'topology_id',
    'traffic_tool',
    'attack_protocol',
    'attack_rate',
    'attacker_count',
    'target_host',
    'collection_timestamp',
]

LEGACY_DEFAULTS = {
    'run_id': 'unknown',
    'scenario_id': 'legacy_unknown',
    'capture_session_id': 'legacy_unknown',
    'topology_id': 'legacy_unknown',
    'traffic_tool': 'unknown',
    'attack_protocol': 'unknown',
    'attack_rate': 'unknown',
    'attacker_count': -1,
    'target_host': 'unknown',
    'collection_timestamp': '',
}

SOURCE_INDEPENDENT = 'mininet_lab_independent_run'
TOPOLOGY_DEFAULT = 'custom_topo_2s6h_v1'

# Only these destinations are allowed for attack traffic
ALLOWED_LAB_IPV4 = {
    '10.0.0.1',
    '10.0.0.2',
    '10.0.0.3',
    '10.0.0.4',
    '10.0.0.5',
    '10.0.0.6',
}
ALLOWED_LAB_CIDR = '10.0.0.0/24'

SOURCE_FAULT = 'mininet_lab_fault_run'
FAULT_AFFECTED_LINK = 's1-s2'
FAULT_TOPOLOGY_ID = TOPOLOGY_DEFAULT

# Model input for the fault dataset. Ground-truth / identity stay out.
FAULT_MODEL_FEATURES = [
    'packet_count_sum',
    'byte_count_sum',
    'delta_packet_sum',
    'delta_byte_sum',
    'packet_rate_window_sum',
    'byte_rate_window_sum',
    'packet_size_avg_mean',
    'n_flows',
    'rx_bps_core',
    'tx_bps_core',
    'delta_rx_dropped_core',
    'delta_tx_dropped_core',
    'drop_rate_core',
    'delta_rx_errors_core',
    'delta_tx_errors_core',
    'rtt_mean_ms',
    'rtt_min_ms',
    'rtt_max_ms',
    'probe_loss_pct',
    'throughput_mbps',
    'jitter_ms',
]

FAULT_FORBIDDEN_FEATURES = [
    'run_id',
    'scenario_id',
    'fault_label',
    'fault_family',
    'fault_severity',
    'affected_link',
    'configured_bw',
    'configured_loss',
    'configured_delay',
    'ip_src',
    'ip_dst',
    'tp_src',
    'tp_dst',
    'capture_session_id',
    'start_time',
    'end_time',
]
