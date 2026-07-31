#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ryu + Online Isolation Forest (OIF) +Selective learning
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

import csv, time, statistics, math, os, sys
from collections import deque, defaultdict
import numpy as np
import pandas as pd

from sklearn.preprocessing import StandardScaler
import joblib

sys.path.append("/home/$USER/mininet/mininet/Online-Isolation-Forest")
from OnlineIForest import OnlineIForest


def entropy_from_counts(counts):
    total = sum(counts)
    if total <= 0:
        return 0.0
    ent = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            ent -= p * math.log(p)
    return ent


class SentryCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SentryCollector, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.interval = 0.5
        self.port_stats = {}
        self.buffer = defaultdict(dict)
        self.prev_flow_stats = {}
        self.blacklist = set()
        self.ENABLE_MITIGATION = False

        # === WARM-UP PARAMETERS ====        
        self.WARMUP_FILE = "/home/$USER/mininet/mininet/warmup_normal.csv"
        self.SCALER_FILE = "/home/$USER/mininet/mininet/oif_scaler.pkl"

        # === Time-based warm-up ===
        self.WARMUP_DURATION = 180
        self.warmup_start_time = None
        self.warmup_buffer = []
        self.in_warmup_mode = True
        self.warmup_loaded = False

        # === Remove old warm-up/scaler files at each new Ryu execution ===
        for f in [self.WARMUP_FILE, self.SCALER_FILE]:
            if os.path.exists(f):
                os.remove(f)

        self.scaler = None

        # ==== TCP baseline learned during warm-up =====
        self.baseline_tcp_throughput = None
        self.baseline_ratio_tcp = None

        # ==== MICRO-BATCHING PARAMETERS AND QUEUES ====
        self.BATCH_SIZE = 25
        self.learning_queue = defaultdict(lambda: deque(maxlen=self.BATCH_SIZE))

        # === SLIDING WINDOW FOR ABNORMAL EVENTS ====
        self.ABN_SCORE_MAX = 0.28
        self.ABN_WINDOW = 20
        self.ABN_LOW_REQUIRED = 10
        self.abn_low_window = defaultdict(lambda: deque(maxlen=self.ABN_WINDOW))

        #  ==== CONSECUTIVE NORMAL COUNTER =====
        self.NORMAL_CONSEC_REQUIRED = 25
        self.normal_consec_count = defaultdict(int)

        # === SCENARIO PHASE CONTROL =====
        self.SCENARIO_DURATION = 360
        self.ATTACK_START_TIME = 180
        self.ATTACK_END_TIME = 360
        self.operation_start_time = None
        self.attack_start_logged = False        
        self.COLOR_RESET = "\033[0m"
        self.COLOR_GREEN = "\033[92m"
        self.COLOR_YELLOW = "\033[93m"
        self.COLOR_CYAN = "\033[96m"

        # === Initialize OIF ====
        try:
            params = {
                "num_trees": 128,
                "max_leaf_samples": 8,
                "window_size": 1024,
                "type": "fixed",
            }
            self.oif = OnlineIForest.create(**params)
            self.OIF_THRESHOLD = 0.28
            self.logger.info("OIF initialized successfully.")
        except Exception as e:
            self.logger.exception("Error initializing OIF: %s", e)
            self.oif = None
            self.OIF_THRESHOLD = 0.0

        # === PORT-STATE DETECTION PARAMETERS =====        
        self.WINDOW_SIZE = 30
        self.k = 3
        self.th = 0.0026
        self.sigma_floor = 1e-6
        self.series_bytesudp = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))
        self.series_packetsudp = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))
        self.series_bytestcp = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))
        self.series_packetstcp = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))

        self.series_pnf = defaultdict(lambda: defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE)))
        self.series_ppnf = defaultdict(lambda: defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE)))

        # === OUTPUT CSV ====        
        self.csv_file = None
        self.csv_header_written = False

        self.monitor_thread = hub.spawn(self._monitor)

    def _save_warmup(self):
        feature_names = [
            "mean_udp", "cv_udp", "mean_pkt_udp", "entropy_udp",
            "mean_tcp", "cv_tcp", "ratio_tcp", "entropy_tcp",
            "mean_pnf", "mean_ppnf"
        ]

        if not self.warmup_buffer:
            self.logger.warning("Warm-up ended without samples to save.")
            return

        df_save = pd.DataFrame(self.warmup_buffer, columns=feature_names)
        df_save.to_csv(self.WARMUP_FILE, index=False)

        self.baseline_tcp_throughput = float(df_save["mean_tcp"].median())
        self.baseline_ratio_tcp = float(df_save["ratio_tcp"].median())

        scaler = StandardScaler()
        scaler.fit(df_save.values)
        self.scaler = scaler
        joblib.dump(scaler, self.SCALER_FILE)

        if self.oif is not None and len(df_save) > 0:
            X = df_save.values
            X_norm = self.scaler.transform(X)
            self.oif.learn_batch(X_norm)

        self.warmup_loaded = True

        # ==== Transition to operation mode ====
        self.operation_start_time = time.time()
        self.in_warmup_mode = False

        # === Create the operational CSV after warm-up =====
        results_dir = "/home/$USER/mininet/mininet/results"
        os.makedirs(results_dir, exist_ok=True)
#        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.csv_file = os.path.join(results_dir, f"oif_output.csv")

        with open(self.csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "switch", "port",
                "vin_Bps", "vout_Bps", "pnf", "ppnf",
                "mean_udp", "cv_udp", "mean_pkt_udp", "entropy_udp",
                "mean_tcp", "cv_tcp", "ratio_tcp", "entropy_tcp",
                "mean_pnf", "mean_ppnf",
                "port_state", "port_outlier_prop",
                "status", "alert_type", "predict", "prob"
            ])
        self.csv_header_written = True

        self.logger.warning(
            "WARM-UP completed and saved with %d samples (scaler fitted).",
            len(df_save)
        )
        self.logger.warning(
            "Warm-up baselines defined: baseline_tcp_throughput=%.6f | baseline_ratio_tcp=%.6f",
            self.baseline_tcp_throughput,
            self.baseline_ratio_tcp
        )
        self.logger.warning(
            f"{self.COLOR_GREEN}>>> WARM-UP COMPLETED. CSV CREATED AND OPERATION STARTED <<<{self.COLOR_RESET}"
        )

    def _process_learning_batch(self, dpid):
        if self.oif is None:
            return

        queue = self.learning_queue[dpid]
        if not queue:
            return

        batch_to_learn = np.array(list(queue), dtype=float)
        self.oif.learn_batch(batch_to_learn)
        queue.clear()

        self.logger.info(
            f"{self.COLOR_CYAN}[SW {dpid}] OIF UPDATED with a batch of {len(batch_to_learn)} samples.{self.COLOR_RESET}"
        )

    def _allowed_update_switches(self):
        if self.operation_start_time is None:
            return {3, 4, 6, 7}

        elapsed = time.time() - self.operation_start_time

        if self.ATTACK_START_TIME <= elapsed < self.ATTACK_END_TIME:
            return {3, 4, 6, 7}

        return {3, 4, 6, 7}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        self._install_proto_flows(dp)

    def _install_proto_flows(self, dp):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]

        # 1. Proactive TCP and UDP rules (priority 40000)
        for proto in [6, 17]:
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=proto)
            fm = parser.OFPFlowMod(
                datapath=dp, priority=40000, match=match,
                instructions=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            )
            dp.send_msg(fm)

        # 2. Rule to allow ARP traffic (priority 1000)
        match_arp = parser.OFPMatch(eth_type=0x0806)
        fm_arp = parser.OFPFlowMod(
            datapath=dp, priority=1000, match=match_arp,
            instructions=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        )
        dp.send_msg(fm_arp)

        # 3. SILENCE RULE (anti-Packet-In) - priority 10
        match_all = parser.OFPMatch()
        fm_drop = parser.OFPFlowMod(
            datapath=dp, priority=10, match=match_all,
            instructions=[]
        )
        dp.send_msg(fm_drop)
        self.logger.info(f"Flow rules (including the silence rule) installed on switch {dp.id}")

    def _apply_mitigation(self, dpid, src_ip, dst_ip, ip_proto=17):
        if not self.ENABLE_MITIGATION:
            return

        dp = self.datapaths.get(dpid)
        if dp is None:
            self.logger.warning(f"[MITIGATION] Switch {dpid} not found.")
            return

        parser = dp.ofproto_parser
        ofp = dp.ofproto

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
            ip_proto=ip_proto
        )

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=50000,
            match=match,
            instructions=[],
            hard_timeout=30,
            idle_timeout=15
        )

        dp.send_msg(mod)
        self.logger.warning(
            f"[MITIGATION] DROP rule installed on SW {dpid} para {src_ip} -> {dst_ip} proto={ip_proto}"
        )

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                try:
                    dp.send_msg(parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY))
                    dp.send_msg(parser.OFPFlowStatsRequest(
                        dp, 0, dp.ofproto.OFPTT_ALL,
                        dp.ofproto.OFPP_ANY, dp.ofproto.OFPG_ANY,
                        0, 0, parser.OFPMatch(eth_type=0x0800)
                    ))
                except:
                    pass
            hub.sleep(self.interval)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()

        for stat in ev.msg.body:
            port = stat.port_no
            if port <= 0 or port >= 0xff00:
                continue

            vin, vout = stat.tx_bytes, stat.rx_bytes
            key = (dpid, port)

            if key not in self.port_stats:
                self.port_stats[key] = (vin, vout, now)
                continue

            last_vin, last_vout, last_ts = self.port_stats[key]
            dt = now - last_ts
            if dt <= 0:
                continue

            rate_in = max(0, (vin - last_vin) / dt)
            rate_out = max(0, (vout - last_vout) / dt)

            self.port_stats[key] = (vin, vout, now)
            self.buffer[dpid][port] = (rate_in, rate_out)

            pnf = rate_in / rate_out if rate_out > 0 else 0.0
            paired = port + 1 if port % 2 == 1 else port - 1
            ppnf = 0.0
            if paired in self.buffer[dpid]:
                rin_p, rout_p = self.buffer[dpid][paired]
                ppnf = rin_p / rout_p if rout_p > 0 else 0.0

            self.series_pnf[dpid][port].append(pnf)
            self.series_ppnf[dpid][port].append(ppnf)

            self._detect_and_record(dpid, port, rate_in, rate_out, pnf, ppnf)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()

        udp_b = udp_p = tcp_b = tcp_p = 0

        for stat in ev.msg.body:
            proto = None
            try:
                proto = stat.match.get("ip_proto")
            except:
                proto = None

            if proto == 17:
                udp_b += stat.byte_count
                udp_p += stat.packet_count
            elif proto == 6:
                tcp_b += stat.byte_count
                tcp_p += stat.packet_count

        prev = self.prev_flow_stats.get(dpid)
        if prev is None:
            self.prev_flow_stats[dpid] = {
                "t": now, "ub": udp_b, "up": udp_p,
                "tb": tcp_b, "tp": tcp_p
            }
            return

        dt = now - prev["t"]
        if dt <= 0:
            return

        self.series_bytesudp[dpid].append(max(0, (udp_b - prev["ub"]) / dt))
        self.series_packetsudp[dpid].append(max(0, (udp_p - prev["up"]) / dt))
        self.series_bytestcp[dpid].append(max(0, (tcp_b - prev["tb"]) / dt))
        self.series_packetstcp[dpid].append(max(0, (tcp_p - prev["tp"]) / dt))

        self.prev_flow_stats[dpid] = {
            "t": now, "ub": udp_b, "up": udp_p,
            "tb": tcp_b, "tp": tcp_p
        }

    def _detect_and_record(self, dpid, port, rate_in, rate_out, pnf, ppnf):
        # Start the warm-up timer only when the first traffic sample arrives
        if self.in_warmup_mode and self.warmup_start_time is None:
            self.warmup_start_time = time.time()
            self.logger.warning(">>> WARM-UP STARTED WITH THE FIRST TRAFFIC SAMPLE <<<")

        # Automatically transition from warm-up after WARMUP_DURATION seconds of actual collection
        if (
            self.in_warmup_mode and
            self.warmup_start_time is not None and
            (time.time() - self.warmup_start_time) >= self.WARMUP_DURATION
        ):
            self._save_warmup()

        if (
            (not self.in_warmup_mode) and
            (self.operation_start_time is not None) and
            (not self.attack_start_logged)
        ):
            elapsed = time.time() - self.operation_start_time
            if elapsed >= self.ATTACK_START_TIME:
                self.logger.warning(
                    f"{self.COLOR_YELLOW}>>> ATTACK PERIOD STARTED <<<{self.COLOR_RESET}"
                )
                self.attack_start_logged = True

        now_ts = time.strftime("%Y-%m-%d %H:%M:%S")

        b_udp = list(self.series_bytesudp[dpid])
        p_udp = list(self.series_packetsudp[dpid])
        b_tcp = list(self.series_bytestcp[dpid])
        p_tcp = list(self.series_packetstcp[dpid])

        mean_udp = statistics.mean(b_udp) if b_udp else 0.0
        cv_udp = statistics.pstdev(b_udp) / mean_udp if len(b_udp) > 1 and mean_udp > 0 else 0.0
        mean_pkt_udp = statistics.mean(p_udp) if p_udp else 0.0
        entropy_udp = entropy_from_counts(p_udp) if p_udp else 0.0

        mean_tcp = statistics.mean(b_tcp) if b_tcp else 0.0
        cv_tcp = statistics.pstdev(b_tcp) / mean_tcp if len(b_tcp) > 1 and mean_tcp > 0 else 0.0
        ratio_tcp = mean_tcp / (mean_tcp + mean_udp) if (mean_tcp + mean_udp) > 0 else 0.0
        entropy_tcp = entropy_from_counts(p_tcp) if p_tcp else 0.0

        mean_pnf = statistics.mean(self.series_pnf[dpid][port]) if self.series_pnf[dpid][port] else 0.0
        mean_ppnf = statistics.mean(self.series_ppnf[dpid][port]) if self.series_ppnf[dpid][port] else 0.0

        pnf_series = list(self.series_pnf[dpid][port])
        port_outlier_prop = 0

        tcp_throughput_ok = tcp_composition_ok = True

        if len(pnf_series) >= 5:
            mu = float(np.mean(pnf_series))
            sigma = float(np.std(pnf_series, ddof=0))
            sigma = max(sigma, self.sigma_floor)
            diffs = np.abs(np.array(pnf_series) - mu)
            port_outlier_prop = float(np.mean(diffs > (self.k * sigma)))

            stats_abnormal = port_outlier_prop > self.th

            if not self.in_warmup_mode:
                tcp_throughput_ok = (
                    self.baseline_tcp_throughput is not None and
                    mean_tcp >= (0.95 * self.baseline_tcp_throughput)
                )
                tcp_composition_ok = (
                    self.baseline_ratio_tcp is not None and
                    ratio_tcp >= (0.95 * self.baseline_ratio_tcp)
                )

                if stats_abnormal or not tcp_throughput_ok or not tcp_composition_ok:
                    port_state = "abnormal"
                else:
                    port_state = "normal"
            else:
                port_state = "abnormal" if stats_abnormal else "normal"
        else:
            port_state = "normal"

        feat_vec_list = [
            mean_udp, cv_udp, mean_pkt_udp, entropy_udp,
            mean_tcp, cv_tcp, ratio_tcp, entropy_tcp,
            mean_pnf, mean_ppnf
        ]
        feat_vec = np.array(feat_vec_list, dtype=float).reshape(1, -1)

        if self.scaler is not None:
            try:
                feat_vec_norm = self.scaler.transform(feat_vec)
            except Exception:
                feat_vec_norm = feat_vec
        else:
            feat_vec_norm = feat_vec

        predict = "-"
        prob = "-"
        status = "NORM"
        alert_type = "OK"

        if self.in_warmup_mode:
            if dpid in [3, 4, 6, 7]:
                self.warmup_buffer.append(feat_vec_list)

            status = "WARMUP"
            alert_type = f"COLLECTING({len(self.warmup_buffer)})"

        else:
            if self.operation_start_time is None:
                self.operation_start_time = time.time()

            keyp = (dpid, port)

            if port_state == "normal":
                self.normal_consec_count[keyp] += 1

                if self.oif is not None:
                    win = self.abn_low_window[keyp]
                    low_count = int(sum(win))
                    allowed_switches = self._allowed_update_switches()

                    if (
                        dpid in allowed_switches and
                        self.normal_consec_count[keyp] >= self.NORMAL_CONSEC_REQUIRED and
                        #low_count >= self.ABN_LOW_REQUIRED and
                        tcp_throughput_ok and
                        tcp_composition_ok
                    ):
                        self.learning_queue[dpid].append(feat_vec_norm[0])
                        if len(self.learning_queue[dpid]) >= self.BATCH_SIZE:
                            self._process_learning_batch(dpid)
                        status = "NORM"
                        alert_type = (
                            f"LEARN_OK(normal_seq={self.normal_consec_count[keyp]},"
                            f" low_count={low_count},"
                            f" v_tcp_ok={int(tcp_throughput_ok)},"
                            f" c_tcp_ok={int(tcp_composition_ok)})"
                        )
                    else:
                        status = "NORM"
                        alert_type = (
                            f"FROZEN(normal_seq={self.normal_consec_count[keyp]},"
                            f" low_count={low_count},"
                            f" v_tcp_ok={int(tcp_throughput_ok)},"
                            f" c_tcp_ok={int(tcp_composition_ok)})"
                        )

            else:
                self.normal_consec_count[keyp] = 0

                if self.oif is not None:
                    t_start = time.time()
                    scores = self.oif.score_batch(feat_vec_norm)
                    t_end = time.time()

                    prob = round(float(scores[0]), 6)

                    self.abn_low_window[keyp].append(1 if prob <= self.ABN_SCORE_MAX else 0)

                    if prob > self.OIF_THRESHOLD:
                        predict = 1
                        status = "OIF_ALERT"
                        alert_type = f"OIF({prob})"

                        self._apply_mitigation(dpid, "10.0.0.1", "10.0.0.5", 17)
                        self._apply_mitigation(dpid, "10.0.0.2", "10.0.0.5", 17)

                        reaction_ms = (t_end - t_start) * 1000.0
                        self.logger.info(
                            f" LDoS ALERT! [SW {dpid}] Port {port} | Reaction Time: {reaction_ms:.3f} ms"
                        )
                    else:
                        predict = 0
                        status = "PORT_ALERT"
                        alert_type = f"Port({prob})"

                        reaction_ms = (t_end - t_start) * 1000.0
                        self.logger.info(
                            f"[SW {dpid}] Port {port} | Reaction Time: {reaction_ms:.3f} ms"
                        )

        if (not self.in_warmup_mode) and self.csv_file:
            with open(self.csv_file, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    now_ts, dpid, port,
                    f"{rate_in:.2f}", f"{rate_out:.2f}", f"{pnf:.6f}", f"{ppnf:.6f}",
                    f"{mean_udp:.6f}", f"{cv_udp:.6f}", f"{mean_pkt_udp:.6f}", f"{entropy_udp:.6f}",
                    f"{mean_tcp:.6f}", f"{cv_tcp:.6f}", f"{ratio_tcp:.6f}", f"{entropy_tcp:.6f}",
                    f"{mean_pnf:.6f}", f"{mean_ppnf:.6f}",
                    port_state, f"{port_outlier_prop:.6f}",
                    status, alert_type, predict, prob
                ])

        self.logger.info(
            f"[SW {dpid}] Port {port} | mode={'WARMUP' if self.in_warmup_mode else 'OP'} "
            f"| port={port_state} | status={status} | score={prob}"
        )

#EOF
