# HUFLIT FortiGate audit for SDN benchmark

**Re-checked 2026-08-17** after moving the corpus to a shared disk path.

Canonical files: `D:\huflit-campus-logs`  
SOICT old path is a junction: `D:\tu_projects\LatexProject\soict2026\data\raw\huflit_logs`  
Public CICIDS/InSDN stays at `D:\huflit_logs\public_datasets` (different corpus).

## Decision for the K29 SDN thesis

**Do not switch the primary benchmark to this HUFLIT dump.**

Keep:

- train / LOSO / realtime controller on Mininet OpenFlow (`dataset/flow_stats_grouped.csv`)
- CICIDS2017 / InSDN as *external* flow benchmarks only
- HUFLIT campus logs as a **qualitative appendix / defense talking point**, not as controller training data

Switching the thesis onto this dump would raise fail risk, not lower it.

## Why they were audited

The lab Mininet set looks toy-like to a committee, and the dump is HUFLIT-permitted. The question was whether it can replace OpenFlow snapshots as the main table.

## What is actually on disk (no unzip)

Measured 2026-08-17, already-extracted only:

| Item | Size |
|---|---|
| Whole `soict2026/data` before move | 36.87 GB |
| `huflit_logs` extracted tree | 32.51 GB |
| `Thang6.rar` (kept compressed) | 4.45 GB / **~21.1 GB if extracted** |
| Largest file | `16062026/forti-svh_.../fortigate.csv` **10.86 GB** |
| Sample `16062026/fortigate.csv` | 1.19 GB, ~1.87M rows |

Inner zips under date folders are still compressed. `16062026/forti-svh_*.zip` and `.rar` are **already extracted**. Extracting `Thang6.rar` would duplicate ~21 GB.

## Modality mismatch

FortiGate / nginx / apache / sshd logs. Sample FortiGate columns include `action`, `attack`, `attackid`, `bytes`, `srcip`, `dstip`, appliance fields.

This is **not** the controller schema:

- `ip_proto`, `tp_src`, `tp_dst`, `packet_count`, `byte_count`, `duration_sec`, `packet_count_per_sec`, `byte_count_per_sec`, `packet_size_avg`, `flow_duration`

A 80k-row sample of `16062026/fortigate.csv` was almost all `type=traffic` with **empty `attack`**. IPS/UTM hits are sparse (the 15–16 Jun FortiGate report lists 163 IPS events on 1.87M logs). There is no `normal / ddos / portscan` label compatible with the 3-class controller.

## Why switching the thesis would make a fail more likely

1. **Wrong topic.** Title and demo are SDN / OpenFlow / os-ken / Mininet DROP. Campus syslog is a different thesis.
2. **Overlap with SOICT 2026.** Same student + advisor already use this 19+ GB corpus as the *primary* dataset of the log-anomaly / LLM RCA paper. Making KLTN ride the same dump looks like topic hijack / double use, not a save.
3. **No time.** ETL + heuristic labels + rewrite Word/slides/demo is a new project.
4. **Heuristic labels are a new attack surface.** Mapping FortiGate `tcp_syn_flood` / `tcp_port_scan` / IPS names onto DDoS/Portscan is guesswork a committee can kill in one question.
5. **Unzip risk.** Re-extracting archives duplicates 10–21 GB and can stall the machine. That work still would not produce OpenFlow features.

## What actually reduces fail risk (keep doing this)

1. Word + slides cite **only** `reports/binary_realtime_loso_summary.csv` (RF Acc 0.7724, F1-anom 0.7746; XGB Acc 0.7520, F1-anom 0.7556; min attack recall **0**; Normal FPR mean 0.16–0.18). Never headline Acc 0.9999 or the retired 79k LOSO table.
2. Say the dataset is **326,961 OpenFlow 5s snapshots / 113,226 5-tuples / 21 scenarios / 206 runs**, self-collected, Mininet-only. Same 2s6h lab — not CICIDS-scale diversity.
3. Disclose AE/IF failure on LOSO, the nmap hole (min-recall 0), FPR ~0.16–0.32, D2 4-class still weak (~0.38 Acc), no production claim.
4. Optional one-page appendix: HUFLIT FortiGate *does* contain scan/flood IPS names on campus — qualitative motivation, **not** a trained table.
5. Working demo video on the existing controller.

## Safe thesis wording

> Nhóm được phép khảo sát log FortiGate / web / SSH của hạ tầng HUFLIT. Bộ này là syslog thiết bị và access log, khác modality so với Flow Statistics OpenFlow (poll 5 giây) của hệ thống khóa luận, và không có nhãn `normal/ddos/portscan` tương thích controller. Nghiên cứu không dùng bộ log này làm tập huấn luyện hay bảng kết quả chính. Bảng chính vẫn là Leave-One-Scenario-Out trên 21 kịch bản Mininet tự thu. Log campus chỉ minh họa rằng quét cổng và flood xuất hiện trên mạng thật, cùng hướng với hai lớp tấn công lab.
