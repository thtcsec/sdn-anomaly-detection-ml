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
