#!/usr/bin/env python3

import sys
import ipaddress
from collections import defaultdict
import math

def ip_to_int(ip_str):
    """Converts an IPv4 dot-decimal string to an integer."""
    try:
        return int(ipaddress.IPv4Address(ip_str))
    except ValueError:
        return None

def int_to_ip(ip_int):
    """Converts an integer back to an IPv4 dot-decimal string."""
    try:
        return str(ipaddress.IPv4Address(ip_int))
    except ValueError:
        return None

def generate_rules(traffic_file, rules_output_file, backend_ips):
    """
    Simulates the load balancer logic to generate connTbl rules based on traffic.

    Args:
        traffic_file (str): Path to the traffic sample file (expects integer IPs).
        rules_output_file (str): Path to write the generated connTbl rules.
        backend_ips (list): List of available backend server IP strings.
    """

    if not backend_ips:
        print("Error: Backend IP list cannot be empty.", file=sys.stderr)
        sys.exit(1)

    min_load = {i: float('inf') for i in range(4)}
    min_dip = {i: backend_ips[0] for i in range(4)}
    dip_load_counters = defaultdict(int)
    conn_tbl_rules = {}
    seen_src_ip_keys = set()

    print(f"Processing traffic file: {traffic_file}")

    try:
        with open(traffic_file, 'r') as f_traffic:
            for line_num, line in enumerate(f_traffic):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split()
                # Expected format: timestamp pkt_len srcIP dstIP srcPort dstPort proto
                if len(parts) < 7:
                    print(f"Warning: Skipping malformed line {line_num + 1}: {line}", file=sys.stderr)
                    continue

                _timestamp, _pkt_len, src_ip_int_str, dst_ip_int_str, _src_port, _dst_port, _proto, *_ = parts

                try:
                    src_ip_int = int(src_ip_int_str)
                    dst_ip_int = int(dst_ip_int_str)
                except ValueError:
                    print(f"Warning: Skipping line {line_num + 1} due to non-integer IP: '{src_ip_int_str}' or '{dst_ip_int_str}'", file=sys.stderr)
                    continue

                src_ip_key = int_to_ip(src_ip_int)
                if src_ip_key is None:
                     print(f"Warning: Skipping line {line_num + 1} due to invalid srcIP integer: {src_ip_int}", file=sys.stderr)
                     continue
                
                vip_id = dst_ip_int & 0x03

                assigned_dip_str = None

                if src_ip_key not in seen_src_ip_keys:
                    min_current_backend_load = float('inf')
                    best_dip_to_assign = backend_ips[0]

                    for backend_ip in backend_ips:
                        current_backend_load = dip_load_counters.get(backend_ip, 0)
                        if current_backend_load < min_current_backend_load:
                            min_current_backend_load = current_backend_load
                            best_dip_to_assign = backend_ip
                    
                    assigned_dip_str = best_dip_to_assign
                    conn_tbl_rules[src_ip_key] = assigned_dip_str
                    seen_src_ip_keys.add(src_ip_key)
                else:
                    assigned_dip_str = conn_tbl_rules[src_ip_key]

                if assigned_dip_str is None:
                    print(f"Error: Could not assign DIP for srcIP {src_ip_key}", file=sys.stderr)
                    continue

                dip_load_counters[assigned_dip_str] += 1
                cntr = dip_load_counters[assigned_dip_str]

                current_min_load_for_vip = min_load.get(vip_id, float('inf'))
                current_min_dip_for_vip = min_dip.get(vip_id, backend_ips[0])

                if cntr < current_min_load_for_vip:
                    min_load[vip_id] = cntr
                    min_dip[vip_id] = assigned_dip_str
                elif assigned_dip_str == current_min_dip_for_vip:
                    min_load[vip_id] = cntr

    except FileNotFoundError:
        print(f"Error: Traffic file not found: {traffic_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred during traffic processing: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Processed traffic. Generated {len(conn_tbl_rules)} rules.")

    print(f"Writing rules to: {rules_output_file}")
    try:
        with open(rules_output_file, 'w') as f_rules:
            f_rules.write("# Format: src_ip_key assigned_dip_value\n")
            for src_ip_key, dip in sorted(conn_tbl_rules.items()):
                 f_rules.write(f"{src_ip_key} {dip}\n")
        print("Rules file generated successfully.")
    except IOError as e:
        print(f"Error writing rules file '{rules_output_file}': {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    
    default_traffic_file = "traffic_sample.txt"
    default_rules_file = "connTbl_rules.txt"

    traffic_in = sys.argv[1] if len(sys.argv) > 1 else default_traffic_file
    rules_out = sys.argv[2] if len(sys.argv) > 2 else default_rules_file

    # Define the list of available backend IPs
    backend_ips = [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
        "192.168.1.13"
    ]

    generate_rules(traffic_in, rules_out, backend_ips)