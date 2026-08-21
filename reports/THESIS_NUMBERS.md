# Thesis numbers (2026-08-21) — paste from here

Read from disk 2026-08-21. Protocol E D2 is current fault headline. **Do not** headline random-split Acc ~0.999. **Do not** mix fault into anomaly. CICIDS2017 is not the SDN primary. InSDN is appendix. Primary data = Mininet OpenFlow.

## Anomaly pool — `dataset/flow_stats_grouped.csv`

| | |
|---|---|
| Snapshots (5s polls) | **326 961** |
| `run_id` | **206** |
| `scenario_id` | **21** |
| Last-poll 5-tuples | **113 226** (`scenario_held_out_STATUS.csv`) |
| normal / ddos / portscan | **198 810 / 93 648 / 34 503** |

326k = more independent runs on the **same 2s6h lab**, not CICIDS-scale diversity.

History only: 11 283 (bootstrap era) · 79 114 / 32 run / 19 scenario.

## Headline — binary LOSO (`reports/binary_realtime_loso_summary.csv`)

Normal vs Attack · 21 scenarios · first 3 polls · 8 features (no raw ports) · no SMOTE.

| Model | Acc pooled | F1 anom | Attack recall mean (min) | Normal FPR mean (max) |
|-------|------------|---------|--------------------------|------------------------|
| Random Forest | 0.7724 | 0.7746 | 0.7301 (**0**) | 0.1616 (0.2928) |
| XGBoost | 0.7520 | 0.7556 | 0.7223 (**0**) | 0.1805 (0.3150) |
| Autoencoder | 0.4759 | 0.0463 | 0.0495 (0) | 0.0614 (0.0746) |
| Isolation Forest | 0.4665 | 0.0003 | 0.0036 (0) | 0.0484 (0.0638) |

Old 79k LOSO (retired): XGB Acc 0.9191 · F1 0.9544 · min-recall 0.1342 · FPR 0.2469. New table is **worse**; report it anyway. Weak point: min-recall **0** on `portscan_nmap_h4_h1`. Realtime prototype still XGB (~0.44 ms).

## Intermediate / appendix (not Kết quả)

- Grouped-by-run (`grouped_real_only_summary.csv`): RF Acc 0.9931±0.0082 F1-macro 0.9863; XGB 0.9937±0.0049 / 0.9872 — scenario overlap remains.
- Random-flow (`model_comparison.csv`): XGB/RF Acc ~0.9999 — leakage.

## Fault — `dataset/fault_stats_grouped.csv` (Protocol D, historical)

| | |
|---|---|
| Snapshots | **6666** |
| `run_id` / `scenario_id` | **324 / 36** |
| Labels | delay 1864 · bandwidth 1857 · loss 1839 · normal 1106 |

LOSO pooled n_test = 5370 (`fault_protocol_d*_loso.csv` `_pooled` rows).

| Protocol | Question | RF Acc / F1-macro | XGB Acc / F1-macro |
|----------|----------|-------------------|--------------------|
| **D1** | detect fault vs normal | **0.9339 / 0.8636** | 0.9272 / 0.8527 |
| **D2** | 4-class bw/loss/delay/normal | 0.3726 / 0.4168 | **0.3793 / 0.4200** |

**D2 Protocol D is still weak** (~0.37–0.38 Acc, ~0.42 F1). Root cause: `tc` never attached to OVS ports + iperf probe stayed on the same switch. Do not claim type classification from this table.

## Fault Protocol E (current D2 headline — do not mix with D)

`dataset/fault_stats_grouped_e.csv` · 1,982 snapshots · **112 `run_id`** · **36 `scenario_id`** · delay 570 · bandwidth 553 · loss 529 · normal 330.

LOSO pooled n_test = 1534 (`reports/fault_protocol_e_d1_loso.csv`, `fault_protocol_e_d2_loso.csv`, `fault_protocol_e_d2_per_class.csv`).

| Protocol | Question | RF Acc / F1-macro | XGB | SVM (RBF) |
|----------|----------|-------------------|-----|-----------|
| **E D1** | detect fault vs normal | **0.981 / 0.965** | 0.976 / 0.955 | 0.968 / 0.941 |
| **E D2** | 4-class bw/loss/delay/normal | **0.923 / 0.926** | 0.902 / 0.903 | 0.886 / 0.889 |

**Headline D2 = RF.** SVM is in the table and worse than RF — do not headline. IF/AE = N/A (binary unsupervised only).

RF D2 recall: Bandwidth **0.883** · Loss **0.874** · Delay **0.996** (all ≥ 0.82) · Normal 0.941.

D2 is now allowed for **Protocol E lab only** (Mininet 2s6h, explicit `tc` on OVS + probe h6→h1). Still **not** campus SDN / production.

Protocol D D2 ~0.38 stays historical (broken `tc` + same-switch iperf). Never headline it as current.

## SVM on anomaly binary LOSO (`binary_realtime_loso_summary.csv`)

LinearSVC (dual=False, train cap 40k): Acc **0.7491** · F1 **0.7768** · mean attack recall 0.8524 (min **0**) · Normal FPR mean **0.2871** (max 0.5613). Do not headline over RF (better FPR). Same hole: `portscan_nmap_h4_h1`.

Word cheat sheet: `HUONG_DAN_CHINH_SUA_KHOA_LUAN_DOCX_VA_SLIDES.md`.
