# Dataset schema note (generated; the 326k CSV is NOT in this pack)

`dataset/flow_stats_grouped.csv` is ~96 MB. It is excluded on purpose.
**Trust `reports/*.csv` for Acc/F1.** This note is a streaming header/count only.

## `dataset/flow_stats_grouped.csv`
- Size: **96.02 MB** (100681739 bytes)
- Lines (incl. header): **326962** → data rows **326961**
- Distinct `run_id`: **206**
- Distinct `scenario_id`: **21**
- `label` counts: ddos=93648, normal=198810, portscan=34503

First <=5 lines:

```
timestamp,datapath_id,flow_id,ip_src,ip_dst,ip_proto,tp_src,tp_dst,packet_count,byte_count,duration_sec,duration_nsec,packet_count_per_sec,byte_count_per_sec,packet_size_avg,flow_duration,label,is_synthetic,source,run_id,scenario_id,capture_session_id,topology_id,traffic_tool,attack_protocol,attack_rate,attacker_count,target_host,collection_timestamp
2026-08-15 12:23:26,2,55864484,10.0.0.1,10.0.0.4,1,0,0,8,784,5,909000000,1.3539,132.679,98.0,5.909,normal,0,mininet_lab_independent_run,run_20260815_122322_1d712a1f,normal_ping_iperf_light,session_20260815_122315,custom_topo_2s6h_v1,iperf/ping,none,unknown,0,10.0.0.4,2026-08-15 12:23:22
2026-08-15 12:23:26,2,22434726,10.0.0.1,10.0.0.5,1,0,0,1,98,5,905000000,0.1693,16.5961,98.0,5.905,normal,0,mininet_lab_independent_run,run_20260815_122322_1d712a1f,normal_ping_iperf_light,session_20260815_122315,custom_topo_2s6h_v1,iperf/ping,none,unknown,0,10.0.0.4,2026-08-15 12:23:22
2026-08-15 12:23:26,2,57710275,10.0.0.1,10.0.0.6,1,0,0,1,98,5,901000000,0.1695,16.6074,98.0,5.901,normal,0,mininet_lab_independent_run,run_20260815_122322_1d712a1f,normal_ping_iperf_light,session_20260815_122315,custom_topo_2s6h_v1,iperf/ping,none,unknown,0,10.0.0.4,2026-08-15 12:23:22
2026-08-15 12:23:26,2,29707055,10.0.0.2,10.0.0.4,1,0,0,1,98,5,891000000,0.1698,16.6355,98.0,5.891,normal,0,mininet_lab_independent_run,run_20260815_122322_1d712a1f,normal_ping_iperf_light,session_20260815_122315,custom_topo_2s6h_v1,iperf/ping,none,unknown,0,10.0.0.4,2026-08-15 12:23:22
```

## `dataset/fault_stats_grouped_e.csv`
- Size: **0.69 MB** (720397 bytes)
- Lines (incl. header): **1983** → data rows **1982**
- Distinct `run_id`: **112**
- Distinct `scenario_id`: **36**

First <=5 lines:

```
timestamp,packet_count_sum,byte_count_sum,delta_packet_sum,delta_byte_sum,packet_rate_window_sum,byte_rate_window_sum,packet_size_avg_mean,duration_sec_mean,n_flows,tcp_delta_packet_sum,tcp_byte_rate_window_sum,n_tcp_flows,udp_delta_packet_sum,udp_byte_rate_window_sum,n_udp_flows,tcp_share,rx_bps_core,tx_bps_core,delta_rx_dropped_core,delta_tx_dropped_core,drop_rate_core,delta_rx_errors_core,delta_tx_errors_core,core_bps,rtt_mean_ms,rtt_min_ms,rtt_max_ms,probe_loss_pct,throughput_mbps,jitter_ms,udp_lost_pct,run_id,scenario_id,fault_label,fault_family,fault_severity,affected_link,configured_bw,configured_loss,configured_delay,traffic,traffic_pair,protocol,source,is_synthetic
2026-08-20 13:03:38,86,8428,58.0,5684.0,11.610899999999999,1137.8365,98.0,5.141944444444444,36,0.0,0.0,0.0,0.0,0.0,0.0,0.0,21665129711.629402,21688654665.116898,0,0,0.0,0,0,43353784376.7463,0.141,0.025,0.574,0.0,55049.99404,,-0.0,fault_20260820_130336_b8025980,EN_high,normal,normal,mixed_high,s1-s2,,,,mixed_high,h1->10.0.0.4,e,mininet_lab_fault_run,0
2026-08-20 13:03:43,3092786,95498817012,2282435.0,70512676756.0,456186.918,14093264731.2971,1726.6506827586206,8.69596551724138,58,2275523.0,14091207004.0807,20.0,6802.0,2055572.6335,2.0,0.9970197057824806,59214730870.2138,59179477436.5371,0,0,0.0,0,0,118394208306.7509,,,,,,,,fault_20260820_130336_b8025980,EN_high,normal,normal,mixed_high,s1-s2,,,,mixed_high,h1->10.0.0.4,e,mininet_lab_fault_run,0
2026-08-20 13:03:48,5611289,173647638170,2518347.0,78148770574.0,503596.955,15627506011.4058,1224.3333555555555,11.480888888888888,90,2510619.0,15625199938.3475,52.0,7620.0,2303956.5629000003,2.0,0.9969740759316332,80522481520.0814,80501915012.9705,0,0,0.0,0,0,161024396533.0519,0.043,0.024,0.074,0.0,37009.931185,,-0.0,fault_20260820_130336_b8025980,EN_high,normal,normal,mixed_high,s1-s2,,,,mixed_high,h1->10.0.0.4,e,mininet_lab_fault_run,0
2026-08-20 13:03:53,8806828,272219527376,2312049.0,70965070154.0,462176.3054,14185847241.5496,1590.3370559701493,13.555097014925373,134,2305131.0,14183784560.4304,92.0,6818.0,2060722.1088,6.0,0.9970509730102178,59127373138.5325,59154878907.5069,0,0,0.0,0,0,118282252046.0394,0.043,0.024,0.074,0.0,37009.931185,,-0.0,fault_20260820_130336_b8025980,EN_high,normal,normal,mixed_high,s1-s2,,,,mixed_high,h1->10.0.0.4,e,mininet_lab_fault_run,0
```

## `dataset/fault_stats_grouped.csv`
- Size: **1.86 MB** (1949018 bytes)
- Lines (incl. header): **6667** → data rows **6666**
- Distinct `run_id`: **324**
- Distinct `scenario_id`: **36**

First <=5 lines:

```
timestamp,packet_count_sum,byte_count_sum,delta_packet_sum,delta_byte_sum,packet_rate_window_sum,byte_rate_window_sum,packet_size_avg_mean,n_flows,rx_bps_core,tx_bps_core,delta_rx_dropped_core,delta_tx_dropped_core,drop_rate_core,delta_rx_errors_core,delta_tx_errors_core,rtt_mean_ms,rtt_min_ms,rtt_max_ms,probe_loss_pct,throughput_mbps,jitter_ms,run_id,scenario_id,fault_label,fault_family,fault_severity,affected_link,configured_bw,configured_loss,configured_delay,traffic,traffic_pair,source,is_synthetic
2026-08-18 14:50:27,116,11368,80.0,7840.0,16.177,1585.3512,98.0,36,8075.9030999999995,8076.221,0,0,0.0,0,0,0.11,0.044,0.26,0.0,39078.076045,,fault_20260818_145024_81f3d4c8,N_ping,normal,normal,ping,s1-s2,,,,ping,h1->10.0.0.4,mininet_lab_fault_run,0
2026-08-18 14:50:32,212,20776,96.0,9408.0,19.177999999999997,1879.4324000000001,98.0,36,8418.401699999999,8418.401699999999,0,0,0.0,0,0,0.063,0.049,0.095,0.0,30440.028377,,fault_20260818_145024_81f3d4c8,N_ping,normal,normal,ping,s1-s2,,,,ping,h1->10.0.0.4,mininet_lab_fault_run,0
2026-08-18 14:50:37,316,30968,104.0,10192.0,20.7962,2038.0248000000001,98.0,36,8466.639299999999,8466.639299999999,0,0,0.0,0,0,0.063,0.049,0.095,0.0,30440.028377,,fault_20260818_145024_81f3d4c8,N_ping,normal,normal,ping,s1-s2,,,,ping,h1->10.0.0.4,mininet_lab_fault_run,0
2026-08-18 14:50:42,400,39200,112.0,10976.0,22.3928,2194.4958,98.0,8,8147.6777999999995,8147.6777999999995,0,0,0.0,0,0,,,,,,,fault_20260818_145024_81f3d4c8,N_ping,normal,normal,ping,s1-s2,,,,ping,h1->10.0.0.4,mininet_lab_fault_run,0
```

Do not treat ~326,961 poll snapshots as 326,961 i.i.d. sessions.
