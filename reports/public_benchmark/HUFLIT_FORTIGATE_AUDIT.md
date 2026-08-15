# HUFLIT FortiGate audit for SDN benchmark

## Decision

Do **not** use the HUFLIT FortiGate logs as the primary benchmark for this repo.

Use them only as an external follow-up experiment if there is time to build a
separate ETL + labeling pipeline.

## Why they were audited

The project needed a less toy-like DDoS benchmark than the original Mininet lab
set, and the user explicitly pointed to:

- `D:\tu_projects\LatexProject\soict2026\data`

## What was found

A sample read of:

- `D:\tu_projects\LatexProject\soict2026\data\raw\huflit_logs\15062026\fortigate.csv`

showed a wide firewall/session log schema with fields such as:

- `action`
- `attack`
- `attackid`
- `bytes`
- many product- and appliance-specific columns

This is **not** the same modality as the current repo, which trains on fixed
OpenFlow-style flow statistics:

- `ip_proto`
- `tp_src`
- `tp_dst`
- `packet_count`
- `byte_count`
- `duration_sec`
- `packet_count_per_sec`
- `byte_count_per_sec`
- `packet_size_avg`
- `flow_duration`

## Blockers

1. There is no direct `normal / ddos / portscan` label schema compatible with
   the current 3-class project.
2. The feature space is different from the current controller-collected flow
   features, so direct reuse would require a separate ETL and feature
   engineering pipeline.
3. Any mapping from FortiGate alert names to `ddos` / `portscan` would be at
   least partly heuristic, which is risky this close to the report deadline.
4. Using it as the main benchmark would blur the thesis story: SDN/OpenFlow lab
   pipeline on one side, campus firewall logs on another.

## Chosen path

For the main benchmark upgrade, use public labeled flow data from CICIDS2017,
because it already provides:

- `BENIGN`
- `DDoS`
- `PortScan`

and can be mapped into the repo's fixed 10-feature schema with much less risk.

## Safe thesis wording

> Nhóm có khảo sát log FortiGate của HUFLIT như một nguồn dữ liệu thực tế bên
> ngoài, tuy nhiên bộ log này khác modality so với flow statistics OpenFlow của
> hệ thống hiện tại và chưa có nhãn `normal/ddos/portscan` tương thích trực
> tiếp. Do giới hạn thời gian, nghiên cứu không dùng bộ log này làm benchmark
> chính mà ưu tiên CICIDS2017 cho phần đánh giá bổ sung.
