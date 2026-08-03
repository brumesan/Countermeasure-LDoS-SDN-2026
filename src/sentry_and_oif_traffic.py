#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Generates test traffic for OIF and Sentry.

import os
from time import sleep
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink


# ====== Configuration ======
CONTROLLER_IP = '127.0.0.1'
CONTROLLER_PORT = 6653

# iperf ports
ATTACK_PORT = 5201
LEGIT_PORT = 5202
BACKGROUND_PORT = 5203  # legitimate UDP traffic

# Paths / logs
ATTACK1_LOG = "/tmp/ldos_attack_h1.log"
ATTACK2_LOG = "/tmp/ldos_attack_h2.log"
LEGIT_CLIENT_LOG = "/tmp/iperf3_c_legit.log"
BACKGROUND_UDP_LOG = "/tmp/iperf3_c_background_h4.log"

# Durations (s)
LEGIT_DURATION = 540

# ===== Attacker 1 control =====
ATTACK1_START_OFFSET = 360
ATTACK1_DURATION = 180

# ===== Attacker 2 control =====
ATTACK2_START_OFFSET = 0
ATTACK2_DURATION = 0

# Interface of the host generating legitimate TCP traffic
IFACE_H3 = "h3-eth0"

# Bottleneck
BOTTLENECK_BW = 45


# ====== Attacker 1 parameters ======
ATTACK1_RATE = 95        # Mbps
ATTACK1_CYCLE = 1.5       # s
ATTACK1_BURST = 0.2      # s

# ====== Attacker 2 parameters ======
ATTACK2_RATE = 0        # Mbps
ATTACK2_CYCLE = 0.0      # s
ATTACK2_BURST = 0.0      # s


# ----- Background UDP traffic parameters -----
BACKGROUND_UDP_RATE = 5

# ----- LDoS attack scripts (Python socket) -----
ATTACKER1_SCRIPT = "/tmp/ldos_udp_attack_train_h1.py"
ATTACKER2_SCRIPT = "/tmp/ldos_udp_attack_train_h2.py"


def ensure_attack_script(script_path):
    code = '''#!/usr/bin/env python3
# ==== coding: utf-8 ====

import socket
import time
import sys
from datetime import datetime


def human_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def main():

    if len(sys.argv) != 7:
        print("Usage: ldos_udp_attack_train.py R T L dst_ip dst_port total_duration", file=sys.stderr)
        sys.exit(1)

    R = float(sys.argv[1])
    T = float(sys.argv[2])
    L = float(sys.argv[3])
    dst_ip = sys.argv[4]
    dst_port = int(sys.argv[5])
    total_duration = float(sys.argv[6])

    pkt_size = 1400
    bits_per_pkt = pkt_size * 8
    rate_bps = R * 1e6

    if rate_bps <= 0 or bits_per_pkt <= 0:
        return

    pps = rate_bps / bits_per_pkt
    interval = 1.0 / pps

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'x' * pkt_size

    end_global = time.time() + total_duration

    print(f"[{human_ts()}] Script started. Target: {dst_ip}:{dst_port} | R={R}Mbps, T={T}s, L={L}s")
    sys.stdout.flush()

    try:

        while True:

            now = time.time()
            if now >= end_global:
                break

            start_burst = now
            burst_bytes = 0

            while True:

                now = time.time()
                if now >= end_global or now - start_burst >= L:
                    break

                try:
                    sock.sendto(payload, (dst_ip, dst_port))
                    burst_bytes += pkt_size
                except:
                    pass

                if interval > 0:
                    time.sleep(interval)

            print(f"[{human_ts()}] Burst completed: {burst_bytes} bytes sent.")
            sys.stdout.flush()

            sleep_time = T - (time.time() - start_burst)

            if sleep_time > 0:
                now = time.time()

                if now >= end_global:
                    break

                remaining = end_global - now
                time.sleep(min(sleep_time, remaining))

    except KeyboardInterrupt:
        pass

    finally:
        print(f"[{human_ts()}] Attack ended.")
        sock.close()


if __name__ == "__main__":
    main()
'''

    with open(script_path, "w", encoding="utf-8") as f:
        f.write(code)

    os.chmod(script_path, 0o755)
    print(f"[INFO] LDoS attack script saved to {script_path}")


def start_iperf_servers(h):
    h.cmd(f"nohup iperf3 -s -p {ATTACK_PORT} >/tmp/iperf3_s_{ATTACK_PORT}.log 2>&1 &")

    if LEGIT_PORT != ATTACK_PORT:
        h.cmd(f"nohup iperf3 -s -p {LEGIT_PORT} >/tmp/iperf3_s_{LEGIT_PORT}.log 2>&1 &")

    if BACKGROUND_PORT not in (ATTACK_PORT, LEGIT_PORT):
        h.cmd(f"nohup iperf3 -s -p {BACKGROUND_PORT} >/tmp/iperf3_s_{BACKGROUND_PORT}.log 2>&1 &")


def remove_qdisc(h, iface):
    h.cmd(f"tc qdisc del dev {iface} root || true")


def start_attack(attacker_host, script_path, log_path, rate, cycle, burst, dst_ip, dst_port, duration, label):
    print(
        f"[INFO] Starting {label}: "
        f"burst={burst}s, cycle={cycle}s, total duration={duration}s, rate={rate}Mbps"
    )

    attack_cmd = (
        f"nohup python3 -u {script_path} "
        f"{rate} {cycle} {burst} {dst_ip} {dst_port} {duration} "
        f">{log_path} 2>&1 &"
    )

    attacker_host.cmd(attack_cmd)


def run_scenario():

    print(
        f"\\n>>> STARTING scenario with 2 attackers:"
        f"\\n    Attacker 1 -> R={ATTACK1_RATE}M, T={ATTACK1_CYCLE}s, L={ATTACK1_BURST}s, "
        f"start={ATTACK1_START_OFFSET}s, duration={ATTACK1_DURATION}s"
        f"\\n    Attacker 2 -> R={ATTACK2_RATE}M, T={ATTACK2_CYCLE}s, L={ATTACK2_BURST}s, "
        f"start={ATTACK2_START_OFFSET}s, duration={ATTACK2_DURATION}s"
    )

    ensure_attack_script(ATTACKER1_SCRIPT)
    ensure_attack_script(ATTACKER2_SCRIPT)

    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        autoSetMacs=True,
        link=TCLink
    )

    
    # == Hosts =====
    
    h1 = net.addHost("h1")  # Attacker 1 - Brasilia
    h2 = net.addHost("h2")  # Attacker 2 - Curitiba
    h3 = net.addHost("h3")  # Legitimate TCP host - Porto Alegre
    h4 = net.addHost("h4")  # Legitimate UDP host - Florianopolis
    h5 = net.addHost("h5")  # Victim - Rio de Janeiro
    
    # === Switches =====
    
    s_brasilia = net.addSwitch("s1")
    s_curitiba = net.addSwitch("s2")
    s_porto_alegre = net.addSwitch("s3")
#    s_belo_horizonte = net.addSwitch("s4")
    s_floripa = net.addSwitch("s4")
    s_sao_paulo = net.addSwitch("s6")
    s_rio = net.addSwitch("s7")

    
    # === Links host-switch (100 Mbps) =====
    
    net.addLink(h1, s_brasilia, bw=100)
    net.addLink(h2, s_curitiba, bw=100)
    net.addLink(h3, s_porto_alegre, bw=100)
    net.addLink(h4, s_floripa, bw=100)
    net.addLink(h5, s_rio, bw=100)

    # ==== Backbone ======

    # Brasilia -> Sao Paulo
    net.addLink(s_brasilia, s_sao_paulo, bw=100)

    # Curitiba -> Sao Paulo
    net.addLink(s_curitiba, s_sao_paulo, bw=100)

    # Porto Alegre -> Florianopolis -> Sao Paulo
    net.addLink(s_porto_alegre, s_floripa, bw=100)
    net.addLink(s_floripa, s_sao_paulo, bw=100)

    # Belo Horizonte -> Sao Paulo
#    net.addLink(s_belo_horizonte, s_sao_paulo, bw=100)

    # Sao Paulo -> Rio (bottleneck)
    net.addLink(s_sao_paulo, s_rio, bw=BOTTLENECK_BW, delay='20ms')

    net.addController(
        'c0',
        controller=RemoteController,
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT
    )

    net.build()
    net.start()

    try:
        victim_ip = h5.IP()

        start_iperf_servers(h5)
        sleep(1)

        # ==== Legitimate TCP traffic =====       
        h3.cmd(
            f"nohup iperf3 -c {victim_ip} -p {LEGIT_PORT} -t {LEGIT_DURATION} -i 1 "
            f">{LEGIT_CLIENT_LOG} 2>&1 &"
        )
        print(f"[INFO] Legitimate TCP traffic started ({LEGIT_DURATION}s).")

        
        # ==== Legitimate UDP traffic ======         
        h4.cmd(
            f"nohup iperf3 -c {victim_ip} -u -b {BACKGROUND_UDP_RATE}M -p {BACKGROUND_PORT} "
            f"-t {LEGIT_DURATION} >{BACKGROUND_UDP_LOG} 2>&1 &"
        )
        print(f"[INFO] Legitimate UDP traffic started ({LEGIT_DURATION}s).")

        
        # === Independent start control for both attacks =====
       
        current_time = 0
        attack_events = sorted([
            ("Attack 1", ATTACK1_START_OFFSET, lambda: start_attack(
                h1, ATTACKER1_SCRIPT, ATTACK1_LOG,
                ATTACK1_RATE, ATTACK1_CYCLE, ATTACK1_BURST,
                victim_ip, ATTACK_PORT, ATTACK1_DURATION, "Attack 1 (h1/Brasilia)"
            )),
            ("Attack 2", ATTACK2_START_OFFSET, lambda: start_attack(
                h2, ATTACKER2_SCRIPT, ATTACK2_LOG,
                ATTACK2_RATE, ATTACK2_CYCLE, ATTACK2_BURST,
                victim_ip, ATTACK_PORT, ATTACK2_DURATION, "Attack 2 (h2/Curitiba)"
            )),
        ], key=lambda x: x[1])

        for _, start_offset, action in attack_events:
            wait_time = start_offset - current_time
            if wait_time > 0:
                sleep(wait_time)
                current_time = start_offset
            action()

        # Wait for the remainder of the experiment
        remaining_time = LEGIT_DURATION - current_time
        if remaining_time > 0:
            sleep(remaining_time + 2)

        for h in (h1, h2, h3, h4, h5):
            h.cmd("pkill -f iperf3 || true")
            h.cmd("pkill -f timeout || true")
            h.cmd("pkill -f ldos_udp_attack_train_h1.py || true")
            h.cmd("pkill -f ldos_udp_attack_train_h2.py || true")

    except Exception as e:
        print(f"[ERROR] during scenario execution: {e}")

    finally:
        try:
            net.stop()
        except Exception:
            pass

    print("\\n Scenario completed.")


if __name__ == "__main__":
    run_scenario()

