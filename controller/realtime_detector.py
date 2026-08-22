"""
Real-time detection controller (os-ken) with optional Auto-Mitigation DROP.

Six artifacts, explicit tasks — do not mix:
  random_forest_binary → binary NORMAL | ANOMALY, 8 port-agnostic features
  xgboost / random_forest / svm → 3-class DDOS | NORMAL | PORTSCAN
  isolation_forest / autoencoder → NORMAL | ANOMALY only
Isolation Forest and Autoencoder cannot name DDoS vs Portscan.
SVM is LinearSVC (sklearn); do not import tensorflow on the OpenFlow thread.

Chạy: python controller/run_realtime.py
"""

import json
import os
import sys
import time
import warnings
from collections import defaultdict
from datetime import datetime

# WSL/SOC has no NVIDIA GPU. Set before joblib unpickle imports libxgboost.
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")

import joblib
import numpy as np
import pandas as pd


def _stdlib_threading():
    """eventlet green threads cannot run TensorFlow import — use real OS threads."""
    try:
        from eventlet import patcher
        return patcher.original("threading")
    except Exception:
        import threading
        return threading


_threading = _stdlib_threading()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "src"))
from model_catalog import (  # noqa: E402
    ALLOWED_MODELS,
    BINARY_MODELS,
    FEATURE_COLS,
    artifact_paths,
    build_flow_features,
    feature_columns,
    force_xgboost_cpu,
    inventory,
    missing_artifacts,
    model_task,
    train_hint,
)
from mitigation_policy import (  # noqa: E402
    BLOCK_FLOW_PRIORITY as BLOCK_PRIORITY,
    DEFAULT_ALERT_THRESHOLD,
    update_consecutive_poll_streaks,
)

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from os_ken.lib import hub

MODELS_DIR = os.path.join(BASE_DIR, 'models')
ALERT_LOG = os.path.join(BASE_DIR, 'dataset', 'alerts.json')
LIVE_STATS_LOG = os.path.join(BASE_DIR, 'dataset', 'live_stats.json')
CONFIG_PATH = os.path.join(BASE_DIR, 'dataset', 'controller_config.json')

MAX_ALERTS = 500
MAX_RECENT_FLOWS = 50
BLOCK_COOKIE = 0x53444E424C4F434B  # ASCII-ish "SDNBLOCK"
LABEL_MAP = {0: 'DDOS', 1: 'NORMAL', 2: 'PORTSCAN'}
ALERT_LABELS = frozenset({'DDOS', 'PORTSCAN', 'ANOMALY'})

DEFAULT_CONFIG = {
    'polling_interval': 5.0,
    'alert_threshold': DEFAULT_ALERT_THRESHOLD,
    'block_timeout': 120,
    'mitigation_enabled': True,
    'selected_model': 'random_forest_binary'
}

# First TensorFlow import on WSL/CPU is 30–90s of silence without these.
LOAD_TIMEOUT_SEC = {
    'random_forest_binary': 60,
    'xgboost': 30,
    'random_forest': 60,
    'svm': 30,
    'isolation_forest': 45,
    'autoencoder': 180,
}
LOAD_RETRY_COOLDOWN_SEC = 45


class RealtimeDetector(app_manager.OSKenApp):
    """Controller với khả năng phát hiện tấn công real-time."""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RealtimeDetector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

        # Mitigation & Dynamic Config State
        self.monitor_interval = 5.0
        self.alert_threshold = DEFAULT_ALERT_THRESHOLD
        self.block_timeout = 120
        self.mitigation_enabled = True
        self.selected_model_name = 'random_forest_binary'

        self.alert_counter = defaultdict(int)  # IP → số poll liên tiếp bất thường
        self.blocked_ips = set()               # Danh sách IP đã bị block
        self._blocked_switches_by_ip = defaultdict(set)
        self._poll_generation = 0
        self._poll_observations = None
        self.flows_analyzed = 0
        self.normal_count = 0
        self.ddos_count = 0
        self.portscan_count = 0
        self.anomaly_count = 0
        self.recent_flows = []
        self.last_inference_latency_ms = 0.0
        self.ae_threshold = None
        self.model_task = 'multiclass'
        self.model_artifact = ''
        self.active_feature_cols = list(FEATURE_COLS)
        self._prev_packets = {}
        self._result_lock = _threading.Lock()
        self._load_result = None
        self._loading = False
        self._load_target = ''
        self._load_started = 0.0
        self._load_timeout_sec = 60
        self._load_generation = 0
        self._load_thread = None
        self._load_fail_until = {}
        self.model_load_status = 'idle'
        self.model_load_message = ''
        self._load_heartbeat_at = 0.0

        # Initial config & model load (async — AE/TF must not freeze OpenFlow)
        self.model = None
        self.scaler = None
        self.selected_model_name = ''
        self._reload_config(initial=True)
        self._log_artifact_inventory()

        self.monitor_thread = hub.spawn(self._monitor)

        # Reset alert log & live stats khi start controller
        os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)
        with open(ALERT_LOG, 'w', encoding='utf-8') as f:
            json.dump([], f)
        self._save_live_stats()

    def _reload_config(self, initial=False):
        """Đọc dynamic config từ dataset/controller_config.json nếu có."""
        cfg = dict(DEFAULT_CONFIG)
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                    saved = json.load(f)
                    if isinstance(saved, dict):
                        cfg.update(saved)
            except Exception:
                pass
        else:
            try:
                os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
                with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                    json.dump(cfg, f, indent=2)
            except Exception:
                pass

        self.monitor_interval = max(1.0, min(30.0, float(cfg.get('polling_interval', 5.0))))
        self.alert_threshold = max(1, min(20, int(cfg.get('alert_threshold', DEFAULT_ALERT_THRESHOLD))))
        self.block_timeout = max(10, min(1200, int(cfg.get('block_timeout', 120))))
        self.mitigation_enabled = bool(cfg.get('mitigation_enabled', True))

        target_model = str(cfg.get('selected_model', 'random_forest_binary')).lower()
        if target_model not in ALLOWED_MODELS:
            self.logger.warning("[!] Config selected_model=%s not allowed — ignored", target_model)
        elif initial or target_model != self.selected_model_name or self.model is None:
            self._begin_model_load(target_model)

    def _log_artifact_inventory(self):
        """RAM chỉ giữ 1 model. Năm file vẫn nằm trong models/; đổi ở Cấu hình SOC."""
        try:
            import sklearn
            sk_ver = sklearn.__version__
        except Exception:
            sk_ver = "?"
        self.logger.info(
            "sklearn=%s (thesis lock 1.7.2). InconsistentVersionWarning "
            "is a pickle-version mismatch, not a missing algorithm.",
            sk_ver,
        )
        inv = inventory(MODELS_DIR)
        self.logger.info(
            "Active model = %s. Other algorithms load when selected in Settings, "
            "not all five at process start.",
            self.selected_model_name or (self._load_target + ' (loading)') or 'none',
        )
        for name in ALLOWED_MODELS:
            info = inv.get(name) or {}
            mark = "OK on disk" if info.get("available") else (
                "MISSING " + ",".join(info.get("missing") or [])
            )
            role = "ACTIVE now" if name == self.selected_model_name else info.get("task")
            self.logger.info("  artifact %-18s %s  (%s)", name, mark, role)

    def _validate_loaded(self, model_name, model, scaler, ae_threshold):
        n_feat = len(feature_columns(model_name))
        n_in = getattr(scaler, "n_features_in_", None)
        if n_in is not None and int(n_in) != n_feat:
            raise ValueError(f"{model_name} scaler n_features_in_={n_in}, expected {n_feat}")
        if model_name in ("xgboost", "random_forest", "svm"):
            classes = getattr(model, "classes_", None)
            if classes is not None and set(int(c) for c in classes) != {0, 1, 2}:
                raise ValueError(f"{model_name} classes_={list(classes)}, expected [0,1,2]")
        if model_name == "random_forest_binary":
            classes = getattr(model, "classes_", None)
            if classes is not None and set(int(c) for c in classes) != {0, 1}:
                raise ValueError(
                    f"random_forest_binary classes_={list(classes)}, expected [0,1]"
                )
        if model_name == "isolation_forest":
            n_m = getattr(model, "n_features_in_", None)
            if n_m is not None and int(n_m) != n_feat:
                raise ValueError(f"isolation_forest n_features_in_={n_m}, expected {n_feat}")
        if model_name == "autoencoder":
            shape = model.input_shape
            if isinstance(shape, list):
                shape = shape[0]
            if shape is None or int(shape[-1]) != n_feat:
                raise ValueError(f"autoencoder input_shape={shape}, expected (*, {n_feat})")
            if ae_threshold is None:
                raise ValueError("autoencoder_threshold.pkl has no usable threshold")

    def _begin_model_load(self, model_name):
        """Kick an OS-thread load. Never block the eventlet OpenFlow hub."""
        model_name = str(model_name).lower()
        if model_name not in ALLOWED_MODELS:
            return
        if self._loading:
            return
        if model_name == self.selected_model_name and self.model is not None:
            return
        thread = self._load_thread
        if thread is not None and thread.is_alive():
            self.logger.info(
                "[*] Native load thread still running (%s) — not starting a second import",
                self._load_target or model_name,
            )
            return
        until = float(self._load_fail_until.get(model_name, 0) or 0)
        now = time.time()
        if now < until:
            left = int(until - now)
            self.model_load_status = 'cooldown'
            self.model_load_message = (
                f"{model_name} nạp fail/timeout — thử lại sau {left}s. "
                f"Đang giữ {self.selected_model_name or 'none'}."
            )
            return
        missing = missing_artifacts(MODELS_DIR, model_name)
        if missing:
            self.model_load_status = 'error'
            self.model_load_message = f"Thiếu file: {missing}. {train_hint(model_name)}"
            self.logger.warning(
                "[!] Cannot load %s, missing: %s. Run: %s",
                model_name, missing, train_hint(model_name),
            )
            self._save_live_stats()
            return

        timeout = int(LOAD_TIMEOUT_SEC.get(model_name, 60))
        self._load_generation += 1
        gen = self._load_generation
        self._loading = True
        self._load_target = model_name
        self._load_started = now
        self._load_timeout_sec = timeout
        self._load_heartbeat_at = 0.0
        self.model_load_status = 'loading'
        self.model_load_message = (
            f"Đang nạp {model_name} (timeout {timeout}s). "
            + ("TensorFlow lần đầu trên WSL/CPU thường 30–90s." if model_name == 'autoencoder'
               else "Unpickle sklearn/xgboost.")
        )
        print(
            f"[*] LOADING {model_name.upper()} timeout={timeout}s "
            f"(OpenFlow vẫn chạy; model hiện tại={self.selected_model_name or 'none'})",
            flush=True,
        )
        self.logger.info("[*] LOADING %s timeout=%ss", model_name, timeout)
        self._save_live_stats()
        self._load_thread = _threading.Thread(
            target=self._load_model_worker,
            args=(model_name, gen),
            name=f"model-load-{model_name}",
            daemon=True,
        )
        self._load_thread.start()

    def _load_artifacts(self, model_name):
        """Blocking native work. Must not run on the eventlet hub thread."""
        try:
            from sklearn.exceptions import InconsistentVersionWarning
            warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
        except Exception:
            pass
        paths = artifact_paths(MODELS_DIR, model_name)
        manifest_path = paths.get("manifest")
        if manifest_path:
            with open(manifest_path, "r", encoding="utf-8") as handle:
                manifest = json.load(handle)
            if manifest.get("feature_columns") != feature_columns(model_name):
                raise ValueError(
                    f"{model_name} manifest feature schema does not match catalog"
                )
            if manifest.get("task") != model_task(model_name):
                raise ValueError(f"{model_name} manifest task does not match catalog")
        print(f"[*] [{model_name}] 1/3 load scaler {os.path.basename(paths['scaler'])}", flush=True)
        scaler = joblib.load(paths["scaler"])
        ae_threshold = None
        if model_name == "autoencoder":
            os.environ["TF_USE_LEGACY_KERAS"] = "1"
            os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
            os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
            os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
            print(
                "[*] [autoencoder] 2/3 import TensorFlow "
                "(im 30–90s lần đầu là bình thường, không phải treo)",
                flush=True,
            )
            try:
                from tensorflow import keras
            except Exception:
                import tf_keras as keras
            print(
                f"[*] [autoencoder] 3/3 keras.models.load_model "
                f"{os.path.basename(paths['model'])}",
                flush=True,
            )
            model = keras.models.load_model(paths["model"])
            thr_obj = joblib.load(paths["threshold"])
            if isinstance(thr_obj, dict) and "threshold" in thr_obj:
                ae_threshold = float(thr_obj["threshold"])
            elif isinstance(thr_obj, (int, float, np.floating)):
                ae_threshold = float(thr_obj)
            else:
                raise ValueError(
                    "autoencoder_threshold.pkl must be a float or dict with key 'threshold'"
                )
        else:
            print(
                f"[*] [{model_name}] 2/3 unpickle {os.path.basename(paths['model'])}",
                flush=True,
            )
            model = joblib.load(paths["model"])
            if model_name == "xgboost":
                force_xgboost_cpu(model)
        print(f"[*] [{model_name}] 3/3 validate artifact", flush=True)
        self._validate_loaded(model_name, model, scaler, ae_threshold)
        return model, scaler, ae_threshold, os.path.basename(paths["model"])

    def _load_model_worker(self, model_name, gen):
        t0 = time.time()
        try:
            model, scaler, ae_threshold, artifact = self._load_artifacts(model_name)
            payload = {
                'ok': True,
                'gen': gen,
                'model_name': model_name,
                'model': model,
                'scaler': scaler,
                'ae_threshold': ae_threshold,
                'artifact': artifact,
                'elapsed': round(time.time() - t0, 1),
            }
        except Exception as exc:
            payload = {
                'ok': False,
                'gen': gen,
                'model_name': model_name,
                'error': str(exc),
                'elapsed': round(time.time() - t0, 1),
            }
        with self._result_lock:
            self._load_result = payload

    def _apply_load_result(self):
        with self._result_lock:
            payload = self._load_result
            self._load_result = None
        if not payload:
            return
        if payload.get('gen') != self._load_generation:
            self.logger.info(
                "[*] Discarded stale load result for %s (timed out or superseded)",
                payload.get('model_name'),
            )
            return
        self._loading = False
        name = payload.get('model_name')
        elapsed = payload.get('elapsed', 0)
        if not payload.get('ok'):
            err = payload.get('error') or 'unknown'
            self.model_load_status = 'error'
            self.model_load_message = f"Nạp {name} fail sau {elapsed}s: {err}. Giữ {self.selected_model_name or 'none'}."
            self._load_fail_until[name] = time.time() + LOAD_RETRY_COOLDOWN_SEC
            self.logger.error("[!] Failed to load model %s: %s — keeping previous model", name, err)
            print(f"[!] LOAD FAIL {name}: {err}", flush=True)
            self._save_live_stats()
            return
        self._commit_loaded_model(
            name,
            payload['model'],
            payload['scaler'],
            payload['ae_threshold'],
            payload['artifact'],
            elapsed,
        )

    def _check_load_timeout(self):
        if not self._loading:
            return
        elapsed = time.time() - self._load_started
        if elapsed < self._load_timeout_sec:
            return
        target = self._load_target
        self._load_generation += 1
        self._loading = False
        self.model_load_status = 'timeout'
        self.model_load_message = (
            f"{target} quá {self._load_timeout_sec}s — giữ "
            f"{self.selected_model_name or 'none'}. Thread native có thể vẫn chạy ngầm; "
            f"lần sau thường nhanh hơn."
        )
        self._load_fail_until[target] = time.time() + LOAD_RETRY_COOLDOWN_SEC
        print(f"[!] LOAD TIMEOUT {target} after {elapsed:.0f}s", flush=True)
        self.logger.error("[!] LOAD TIMEOUT %s after %.0fs", target, elapsed)
        self._save_live_stats()

    def _commit_loaded_model(self, model_name, model, scaler, ae_threshold, artifact, elapsed=0):
        self.model = model
        self.scaler = scaler
        self.ae_threshold = ae_threshold
        self.selected_model_name = model_name
        self.model_task = model_task(model_name)
        self.active_feature_cols = feature_columns(model_name)
        self.model_artifact = artifact
        self.normal_count = 0
        self.ddos_count = 0
        self.portscan_count = 0
        self.anomaly_count = 0
        self.recent_flows = []
        self.model_load_status = 'ok'
        self.model_load_message = f"Đang predict bằng {model_name} ({artifact}, {elapsed}s)"
        self.logger.info(
            "\033[92m[✓] NOW PREDICTING WITH %s (%s) file=%s (load %.1fs)\033[0m",
            model_name.upper(), self.model_task, self.model_artifact, elapsed,
        )
        print(
            f"[✓] NOW PREDICTING WITH {model_name.upper()} "
            f"file={self.model_artifact} task={self.model_task} load={elapsed}s",
            flush=True,
        )
        if model_name == "autoencoder":
            self.logger.info("[*] AE threshold (saved Normal-train MSE): %.6f", self.ae_threshold)
        if model_name in BINARY_MODELS:
            self.logger.info(
                "[*] Binary model: labels are NORMAL / ANOMALY only — not DDoS vs Portscan"
            )
        self.logger.info(
            "\033[92m[✓] Auto-Mitigation: %s (threshold=%d, timeout=%ds, poll=%.1fs)\033[0m",
            "ENABLED" if self.mitigation_enabled else "DISABLED",
            self.alert_threshold, self.block_timeout, self.monitor_interval,
        )
        self._save_live_stats()

    def _predict_label(self, features_scaled_df):
        name = self.selected_model_name
        X = np.asarray(features_scaled_df, dtype=np.float64)
        if name in ("xgboost", "random_forest", "svm"):
            pred = int(self.model.predict(features_scaled_df)[0])
            return LABEL_MAP.get(pred, "UNKNOWN")
        if name == "random_forest_binary":
            pred = int(self.model.predict(features_scaled_df)[0])
            return "ANOMALY" if pred == 1 else "NORMAL" if pred == 0 else "UNKNOWN"
        if name == "isolation_forest":
            raw = int(self.model.predict(X)[0])
            if raw == -1:
                return "ANOMALY"
            if raw == 1:
                return "NORMAL"
            self.logger.warning("[!] IsolationForest.predict returned %s (expected -1 or 1)", raw)
            return "UNKNOWN"
        if name == "autoencoder":
            recon = np.asarray(self.model.predict(X, verbose=0), dtype=np.float64)
            mse = float(np.mean(np.square(X - recon)))
            return "ANOMALY" if mse > float(self.ae_threshold) else "NORMAL"
        return "UNKNOWN"

    def _monitor(self):
        while True:
            self._apply_load_result()
            self._check_load_timeout()
            now = time.time()
            if self._loading and (now - self._load_heartbeat_at) >= 5.0:
                self._load_heartbeat_at = now
                elapsed = now - self._load_started
                line = (
                    f"[*] LOADING {self._load_target} "
                    f"{elapsed:.0f}/{self._load_timeout_sec}s "
                    f"— OpenFlow OK, predicting={self.selected_model_name or 'none'}"
                )
                print(line, flush=True)
                self.logger.info(line)
                self.model_load_message = (
                    f"Đang nạp {self._load_target} {elapsed:.0f}/{self._load_timeout_sec}s"
                )
            self._reload_config()
            self._finalize_poll_observations(force=True)
            self._poll_generation += 1
            self._poll_observations = {
                'generation': self._poll_generation,
                'seen_dpids': set(),
                'observed_ips': set(),
                'anomalous_ips': set(),
                'labels_by_ip': defaultdict(set),
            }
            for dp_id, dp in self.datapaths.items():
                self._request_stats(dp)
            self._save_live_stats()
            hub.sleep(self.monitor_interval)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # Table-miss must not idle-expire. idle_timeout=60 emptied the table;
        # fail_mode=secure then dropped packets → dashboard stuck at 0 flows.
        self._add_flow(datapath, 0, match, actions, idle_timeout=0, hard_timeout=0)
        self.datapaths[datapath.id] = datapath
        self.logger.info("Switch connected: dpid=%s", datapath.id)
        self._save_live_stats()

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None,
                  idle_timeout=60, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            instructions=inst,
        )
        if buffer_id:
            kwargs['buffer_id'] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                udp_pkt = pkt.get_protocol(udp.udp)
                if tcp_pkt:
                    match = parser.OFPMatch(
                        in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                        ip_proto=ip_pkt.proto,
                        tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port)
                elif udp_pkt:
                    match = parser.OFPMatch(
                        in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                        ip_proto=ip_pkt.proto,
                        udp_src=udp_pkt.src_port, udp_dst=udp_pkt.dst_port)
                else:
                    match = parser.OFPMatch(
                        in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                        ip_proto=ip_pkt.proto)
            else:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=eth.ethertype,
                    eth_dst=dst,
                    eth_src=src,
                )

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self._add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Thu thập flow stats và predict real-time."""
        if self.model is None:
            return

        body = ev.msg.body
        datapath = ev.msg.datapath
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        updated_any = False

        for stat in body:
            if 'ipv4_src' not in stat.match or 'ipv4_dst' not in stat.match:
                continue

            ip_proto = stat.match.get('ip_proto', 0)
            tp_src = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
            tp_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))

            feature_values = build_flow_features(
                ip_proto=ip_proto,
                tp_src=tp_src,
                tp_dst=tp_dst,
                packet_count=stat.packet_count,
                byte_count=stat.byte_count,
                duration_sec=stat.duration_sec,
                duration_nsec=stat.duration_nsec,
            )
            pkt_per_sec = feature_values['packet_count_per_sec']
            byte_per_sec = feature_values['byte_count_per_sec']
            features = pd.DataFrame(
                [[feature_values[col] for col in self.active_feature_cols]],
                columns=self.active_feature_cols,
            )

            t0 = time.perf_counter()
            features_scaled = pd.DataFrame(
                self.scaler.transform(features),
                columns=self.active_feature_cols,
            )
            label = self._predict_label(features_scaled)
            inf_time = (time.perf_counter() - t0) * 1000.0  # in ms
            self.last_inference_latency_ms = round(inf_time, 3)

            self.flows_analyzed += 1
            updated_any = True

            if label == 'NORMAL':
                self.normal_count += 1
            elif label == 'DDOS':
                self.ddos_count += 1
            elif label == 'PORTSCAN':
                self.portscan_count += 1
            elif label == 'ANOMALY':
                self.anomaly_count += 1
            else:
                self.logger.warning("[!] Unmapped prediction %s — not counted as a class", label)

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            is_blocked = (ip_src in self.blocked_ips)
            self._record_poll_observation(ip_src, label)

            flow_key = (
                int(datapath.id),
                str(ip_src),
                str(ip_dst),
                int(tp_src),
                int(tp_dst),
                int(ip_proto),
            )
            prev_pkts = self._prev_packets.get(flow_key)
            cur_pkts = int(stat.packet_count)
            if prev_pkts is None:
                delta_pps = 0.0
            else:
                delta_pps = max(0, cur_pkts - prev_pkts) / max(0.1, float(self.monitor_interval))
            self._prev_packets[flow_key] = cur_pkts

            # Record recent flow (kể cả Normal)
            flow_entry = {
                'timestamp': timestamp,
                'ip_src': ip_src,
                'ip_dst': ip_dst,
                'tp_src': int(tp_src),
                'tp_dst': int(tp_dst),
                'ip_proto': int(ip_proto),
                'packet_count': int(stat.packet_count),
                'packet_count_per_sec': round(float(pkt_per_sec), 1),
                'packet_delta_per_sec': round(float(delta_pps), 1),
                'byte_count_per_sec': round(float(byte_per_sec), 1),
                'prediction': label,
                'blocked': is_blocked,
                'model': self.selected_model_name,
                'latency_ms': self.last_inference_latency_ms
            }
            self.recent_flows.append(flow_entry)
            if len(self.recent_flows) > MAX_RECENT_FLOWS:
                self.recent_flows = self.recent_flows[-MAX_RECENT_FLOWS:]

            # Alert on attack / anomaly labels only — never invent DDoS from ANOMALY
            if label in ALERT_LABELS:
                alert_line = (
                    f"ALERT [{timestamp}] {ip_src} -> {ip_dst} | proto={ip_proto} | "
                    f"pkts/s={pkt_per_sec:.1f} | bytes/s={byte_per_sec:.1f} | "
                    f"prediction={label}"
                )
                print(f"\033[91m⚠️  {alert_line}\033[0m", flush=True)
                self.logger.warning(
                    "\033[91m⚠️  %s (latency=%.3fms)\033[0m",
                    alert_line, self.last_inference_latency_ms
                )

                self._append_alert({
                    'timestamp': timestamp,
                    'ip_src': ip_src,
                    'ip_dst': ip_dst,
                    'tp_dst': int(tp_dst),
                    'ip_proto': int(ip_proto),
                    'packet_count_per_sec': float(pkt_per_sec),
                    'byte_count_per_sec': float(byte_per_sec),
                    'prediction': label,
                    'blocked': is_blocked,
                    'flows_analyzed': self.flows_analyzed,
                    'latency_ms': self.last_inference_latency_ms
                })

        if self._poll_observations is not None:
            self._poll_observations['seen_dpids'].add(int(datapath.id))
            expected = set(int(dpid) for dpid in self.datapaths)
            if expected and self._poll_observations['seen_dpids'] >= expected:
                self._finalize_poll_observations()

        if updated_any:
            self._save_live_stats()
            print(
                f"[poll] flows={self.flows_analyzed} "
                f"normal={self.normal_count} ddos={self.ddos_count} "
                f"portscan={self.portscan_count} anomaly={self.anomaly_count} "
                f"model={self.selected_model_name}/{self.model_artifact or '-'} "
                f"blocked={sorted(self.blocked_ips) or '-'}",
                flush=True,
            )

    def _record_poll_observation(self, ip_src, label):
        """Aggregate many flow predictions into one source-IP decision per poll."""
        if self._poll_observations is None:
            self._poll_generation += 1
            self._poll_observations = {
                'generation': self._poll_generation,
                'seen_dpids': set(),
                'observed_ips': set(),
                'anomalous_ips': set(),
                'labels_by_ip': defaultdict(set),
            }
        ip_src = str(ip_src)
        self._poll_observations['observed_ips'].add(ip_src)
        self._poll_observations['labels_by_ip'][ip_src].add(str(label))
        if label in ALERT_LABELS:
            self._poll_observations['anomalous_ips'].add(ip_src)

    def _finalize_poll_observations(self, force=False):
        """Update consecutive-poll streaks exactly once per IP and poll cycle."""
        obs = self._poll_observations
        if not obs:
            return
        expected = set(int(dpid) for dpid in self.datapaths)
        if not force and expected and obs['seen_dpids'] < expected:
            return

        incremented = update_consecutive_poll_streaks(
            self.alert_counter,
            obs['anomalous_ips'],
            obs['observed_ips'],
            self.blocked_ips,
        )
        for ip_src in incremented:
            if self.mitigation_enabled and self.alert_counter[ip_src] >= self.alert_threshold:
                labels = sorted(obs['labels_by_ip'].get(ip_src) or {'ANOMALY'})
                datapath = next(iter(self.datapaths.values()), None)
                if datapath is not None:
                    self._block_attacker(datapath, ip_src, '/'.join(labels))
        self._poll_observations = None

    def _save_live_stats(self):
        """Lưu telemetry & live stats ra dataset/live_stats.json cho Dashboard."""
        try:
            payload = {
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'controller_pid': os.getpid(),
                'flows_analyzed': self.flows_analyzed,
                'normal_count': self.normal_count,
                'ddos_count': self.ddos_count,
                'portscan_count': self.portscan_count,
                'anomaly_count': self.anomaly_count,
                'model_task': self.model_task,
                'active_model': self.selected_model_name,
                'model_artifact': self.model_artifact,
                'model_load_status': self.model_load_status,
                'model_load_target': self._load_target,
                'model_load_elapsed_sec': (
                    round(time.time() - self._load_started, 1)
                    if self._loading and self._load_started else 0
                ),
                'model_load_timeout_sec': self._load_timeout_sec,
                'model_load_message': self.model_load_message,
                'blocked_ips': sorted(list(self.blocked_ips)),
                'active_switches': list(self.datapaths.keys()),
                'last_latency_ms': self.last_inference_latency_ms,
                'recent_flows': self.recent_flows[-30:],
                'config': {
                    'polling_interval': self.monitor_interval,
                    'alert_threshold': self.alert_threshold,
                    'block_timeout': self.block_timeout,
                    'mitigation_enabled': self.mitigation_enabled,
                    'selected_model': self.selected_model_name
                }
            }
            tmp = LIVE_STATS_LOG + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            os.replace(tmp, LIVE_STATS_LOG)
        except Exception as exc:
            self.logger.error("[!] Failed to write live stats: %s", exc)

    def _append_alert(self, alert):
        """Ghi alert ra dataset/alerts.json (atomic) để Web Dashboard đọc."""
        try:
            alerts = []
            if os.path.exists(ALERT_LOG):
                with open(ALERT_LOG, 'r', encoding='utf-8') as f:
                    alerts = json.load(f)
                    if not isinstance(alerts, list):
                        alerts = []
            alerts.append(alert)
            if len(alerts) > MAX_ALERTS:
                alerts = alerts[-MAX_ALERTS:]
            tmp_path = ALERT_LOG + '.tmp'
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(alerts, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, ALERT_LOG)
        except (OSError, json.JSONDecodeError) as exc:
            self.logger.error("[!] Failed to write alert log: %s", exc)

    def _block_attacker(self, datapath, attacker_ip, attack_type):
        """
        Cài đặt DROP rule trên TẤT CẢ switches để chặn traffic từ attacker IP.
        Rule có hard_timeout → tự động gỡ sau self.block_timeout giây.
        """
        if attacker_ip in self.blocked_ips:
            return

        self.blocked_ips.add(attacker_ip)
        self._blocked_switches_by_ip[attacker_ip] = set()

        # Cài đặt DROP rule trên TẤT CẢ switches đã kết nối
        for dp_id, dp in self.datapaths.items():
            dp_parser = dp.ofproto_parser
            dp_ofproto = dp.ofproto

            dp_match = dp_parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=attacker_ip
            )
            dp_inst = [dp_parser.OFPInstructionActions(
                dp_ofproto.OFPIT_APPLY_ACTIONS, [])]

            mod = dp_parser.OFPFlowMod(
                datapath=dp,
                cookie=BLOCK_COOKIE,
                priority=BLOCK_PRIORITY,
                match=dp_match,
                instructions=dp_inst,
                hard_timeout=self.block_timeout,  # Tự gỡ sau N giây
                idle_timeout=0,
                flags=dp_ofproto.OFPFF_SEND_FLOW_REM  # Notify khi rule bị xóa
            )
            dp.send_msg(mod)
            dp.send_msg(dp_parser.OFPBarrierRequest(dp))
            self._blocked_switches_by_ip[attacker_ip].add(int(dp_id))

        block_line = (
            f"BLOCKED [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
            f"Attacker IP {attacker_ip} on ALL switches | "
            f"Attack: {attack_type} | Duration: {self.block_timeout}s | "
            f"Alerts: {self.alert_counter[attacker_ip]}"
        )
        print(f"\033[91;1m🚫 {block_line}\033[0m", flush=True)
        self.logger.error("\033[91;1m🚫 %s\033[0m", block_line)

        # Reset counter sau khi block
        self.alert_counter[attacker_ip] = 0

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """Xử lý khi DROP rule hết timeout → unblock IP."""
        msg = ev.msg
        match = msg.match

        if (
            'ipv4_src' in match
            and msg.priority == BLOCK_PRIORITY
            and int(getattr(msg, 'cookie', 0)) == BLOCK_COOKIE
        ):
            unblocked_ip = match['ipv4_src']
            remaining = self._blocked_switches_by_ip.get(unblocked_ip, set())
            remaining.discard(int(msg.datapath.id))
            if unblocked_ip in self.blocked_ips and not remaining:
                self.blocked_ips.discard(unblocked_ip)
                self._blocked_switches_by_ip.pop(unblocked_ip, None)
                self.logger.info(
                    "\033[93m🔓 UNBLOCKED [%s] IP %s - block timeout expired (%ds)\033[0m",
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    unblocked_ip, self.block_timeout
                )

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def openflow_error_handler(self, ev):
        """Surface rejected FlowMods instead of silently claiming mitigation."""
        msg = ev.msg
        self.logger.error(
            "[!] OpenFlow error dpid=%s type=0x%02x code=0x%02x xid=%s",
            getattr(msg.datapath, 'id', '?'), msg.type, msg.code, msg.xid,
        )
