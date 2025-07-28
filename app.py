import os
import uuid
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
import threading
import time
import io
import csv
import json
from datetime import datetime

import traceback
from collections import defaultdict, deque
try:
    from scapy.all import Raw, DNS
except ImportError:
    Raw = None
    DNS = None

# import all your helpers from data_processing.py
from processing.data_processing import (
    clean_dataframe,
    clean_dataframe_in_chunks,
    sort_by_timestamp,
    group_by_timestamp_and_assign_seconds_df,
    process_flow_df,
    compute_statistics_with_warning,
    plot_early_warnings,
    plot_ews_confusion_matrix,
    plot_benign_attack,
    plot_test_peak_region,
    plot_Flow_Packets_s,
    plot_BytesPackets_s,
    plot_dp_dt,
    plot_db_dt,
    plot_d2p_dt2,
    plot_d2b_dt2,
    plot_alert_levels_separately,
    generate_emergency_alerts,
    plot_All_alerts,
    plot_Flow_Packets_s_with_Attack_EWS
)

# --- DDoSAttackDetector class (inserted here for integration) ---
class DDoSAttackDetector:
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'first_seen': None,
            'last_seen': None,
            'flags': set(),
            'ports': set()
        })
        self.time_window = 5
        self.packet_times = deque(maxlen=1000)
        self.port_requests = defaultdict(lambda: deque(maxlen=100))
        self.thresholds = {
            'syn_flood_pps': 100,
            'udp_flood_pps': 200,
            'dns_amplification_ratio': 3.0,
            'ntp_monlist_size': 400,
            'reflection_ratio': 2.0,
            'port_scan_rate': 20
        }
    def detect_attack_type(self, packet):
        timestamp = time.time()
        attack_type = "BENIGN"
        if IP not in packet:
            return attack_type
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flow_key = f"{src_ip}:{dst_ip}"
        self.flow_stats[flow_key]['packet_count'] += 1
        self.flow_stats[flow_key]['byte_count'] += len(packet)
        if not self.flow_stats[flow_key]['first_seen']:
            self.flow_stats[flow_key]['first_seen'] = timestamp
        self.flow_stats[flow_key]['last_seen'] = timestamp
        self.packet_times.append(timestamp)
        if TCP in packet:
            tcp_flags = packet[TCP].flags
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            self.flow_stats[flow_key]['flags'].add(tcp_flags)
            self.flow_stats[flow_key]['ports'].add(dst_port)
            if tcp_flags == 2:
                attack_type = self._detect_syn_flood(src_ip, timestamp)
            elif len(self.flow_stats[flow_key]['ports']) > 10:
                attack_type = self._detect_port_scan(src_ip, timestamp)
            elif dst_port in [80, 443, 8080]:
                attack_type = self._detect_web_ddos(flow_key, timestamp)
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload_size = len(packet[UDP].payload) if packet[UDP].payload else 0
            if DNS and (dst_port == 53 or src_port == 53):
                attack_type = self._detect_dns_amplification(packet, src_port, dst_port, payload_size)
            elif dst_port == 123 or src_port == 123:
                attack_type = self._detect_ntp_amplification(packet, src_port, payload_size)
            elif dst_port == 389 or src_port == 389:
                attack_type = self._detect_ldap_amplification(src_port, payload_size)
            elif dst_port == 1434 or src_port == 1434:
                attack_type = self._detect_mssql_amplification(src_port, payload_size)
            elif dst_port == 137 or src_port == 137:
                attack_type = self._detect_netbios_amplification(src_port, payload_size)
            elif dst_port == 161 or src_port == 161:
                attack_type = self._detect_snmp_amplification(src_port, payload_size)
            elif dst_port == 1900 or src_port == 1900:
                attack_type = self._detect_ssdp_amplification(src_port, payload_size)
            elif dst_port == 69 or src_port == 69:
                attack_type = self._detect_tftp_amplification(src_port, payload_size)
            elif dst_port == 111 or src_port == 111:
                attack_type = self._detect_portmap_amplification(src_port, payload_size)
            else:
                attack_type = self._detect_udp_flood(timestamp)
        return attack_type
    def _detect_syn_flood(self, src_ip, timestamp):
        recent_packets = [t for t in self.packet_times if timestamp - t <= self.time_window]
        if len(recent_packets) > self.thresholds['syn_flood_pps'] * self.time_window:
            return "SYN"
        return "BENIGN"
    def _detect_dns_amplification(self, packet, src_port, dst_port, payload_size):
        if DNS in packet:
            dns_packet = packet[DNS]
            if src_port == 53 and payload_size > 512:
                return "DNS"
            elif dst_port == 53 and dns_packet.qd and dns_packet.qd.qtype in [255, 16]:
                return "DNS"
        return "BENIGN"
    def _detect_ntp_amplification(self, packet, src_port, payload_size):
        if src_port == 123 and payload_size > self.thresholds['ntp_monlist_size']:
            return "NTP"
        elif Raw and Raw in packet:
            payload = bytes(packet[Raw])
            if b'\x17\x00\x03\x2a' in payload:
                return "NTP"
        return "BENIGN"
    def _detect_ldap_amplification(self, src_port, payload_size):
        if src_port == 389 and payload_size > 100:
            return "LDAP"
        return "BENIGN"
    def _detect_mssql_amplification(self, src_port, payload_size):
        if src_port == 1434 and payload_size > 200:
            return "MSSQL"
        return "BENIGN"
    def _detect_netbios_amplification(self, src_port, payload_size):
        if src_port == 137 and payload_size > 50:
            return "NetBIOS"
        return "BENIGN"
    def _detect_snmp_amplification(self, src_port, payload_size):
        if src_port == 161 and payload_size > 100:
            return "SNMP"
        return "BENIGN"
    def _detect_ssdp_amplification(self, src_port, payload_size):
        if src_port == 1900 and payload_size > 200:
            return "SSDP"
        return "BENIGN"
    def _detect_tftp_amplification(self, src_port, payload_size):
        if src_port == 69 and payload_size > 100:
            return "TFTP"
        return "BENIGN"
    def _detect_portmap_amplification(self, src_port, payload_size):
        if src_port == 111 and payload_size > 100:
            return "PortMap"
        return "BENIGN"
    def _detect_udp_flood(self, timestamp):
        recent_packets = [t for t in self.packet_times if timestamp - t <= self.time_window]
        if len(recent_packets) > self.thresholds['udp_flood_pps'] * self.time_window:
            return "UDP"
        return "BENIGN"
    def _detect_port_scan(self, src_ip, timestamp):
        self.port_requests[src_ip].append(timestamp)
        recent_requests = [t for t in self.port_requests[src_ip] if timestamp - t <= self.time_window]
        if len(recent_requests) > self.thresholds['port_scan_rate'] * self.time_window:
            return "PortScan"
        return "BENIGN"
    def _detect_web_ddos(self, flow_key, timestamp):
        flow = self.flow_stats[flow_key]
        duration = timestamp - flow['first_seen']
        if duration > 0:
            request_rate = flow['packet_count'] / duration
            if request_rate > 50:
                return "WebDDoS"
        return "BENIGN"

detector = DDoSAttackDetector()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

UPLOAD_FOLDER = 'uploads'
PLOT_FOLDER   = 'static/plots'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PLOT_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PLOT_FOLDER']   = PLOT_FOLDER

# Global variables for live capture
live_capture_active = False
capture_thread = None
captured_data = []
last_processed_time = time.time()
session_id = None
output_dir = None

def process_file(filepath, session_id):
    # 1) Create a per-session directory for plots
    output_dir = os.path.join(app.config['PLOT_FOLDER'], session_id)
    os.makedirs(output_dir, exist_ok=True)

    print(f"Processing file: {filepath} for session {session_id}")
    
    try:
        # 2) Read & run all your processing steps
        df = pd.read_csv(filepath)
        print(f"Initial DataFrame shape: {df.shape}")
        print(f"Initial columns: {df.columns.tolist()}")
        print(f"Sample data:\n{df.head(2)}")
        
        # Check if this is likely from live capture by looking at the columns
        is_live_capture = 'Timestamp' in df.columns and (
            'flow_bytes_s' in df.columns or 
            'flow_packets_s' in df.columns or
            'Flow_bytes_per_sec' not in df.columns
        )
        
        if is_live_capture:
            print("Detected live capture format - adapting column names")
            
            # Map live capture columns to expected format
            rename_dict = {}
            if 'flow_packets_s' in df.columns:
                rename_dict['flow_packets_s'] = 'Flow_packets_per_sec'
            if 'flow_bytes_s' in df.columns:
                rename_dict['flow_bytes_s'] = 'Flow_bytes_per_sec'
                
            if rename_dict:
                df.rename(columns=rename_dict, inplace=True)
                print(f"Renamed columns: {rename_dict}")
            
            # Ensure Label column is present and correctly capitalized
            if 'Label' not in df.columns and 'label' in df.columns:
                df.rename(columns={'label': 'Label'}, inplace=True)
                
            print(f"DataFrame columns after renaming: {df.columns.tolist()}")
        
        # Run standard processing pipeline
        print("Step 1: Cleaning data...")
        df = clean_dataframe(df)
        print(f"After cleaning shape: {df.shape}")
        
        print("Step 2: Cleaning in chunks...")
        df = clean_dataframe_in_chunks(df, 1000)
        print(f"After chunk cleaning shape: {df.shape}")
        
        print("Step 3: Sorting by timestamp...")
        df = sort_by_timestamp(df)
        print(f"After sorting shape: {df.shape}")
        
        print("Step 4: Grouping by timestamp...")
        df = group_by_timestamp_and_assign_seconds_df(df)
        print(f"After grouping shape: {df.shape}")
        
        print("Step 5: Processing flow data...")
        df = process_flow_df(df)
        print(f"After flow processing shape: {df.shape}")
        
        print("Step 6: Computing statistics and warnings...")
        df = compute_statistics_with_warning(df)
        print(f"After statistics computation shape: {df.shape}")
        print(f"Final columns: {df.columns.tolist()}")

        # 3) Rename for consistency in the JSON/table
        df.rename(columns={
            'Timestamp': 'Seconds',
            'Flow_packets_per_sec': 'Flow Packets/s',
            'Flow_bytes_per_sec': 'Flow Bytes/s'
        }, inplace=True)
        
        print(f"Final columns after renaming: {df.columns.tolist()}")

        # 4) Locate first attack index for that plot
        attack_idxs = np.where(df['Label'] != 'BENIGN')[0]
        first_attack = int(attack_idxs[0]) if len(attack_idxs) else -1
        
        print(f"Found {len(attack_idxs)} attack packets, first at index {first_attack}")

        # 5) Generate all your PNGs
        print("Generating plots...")
        plot_specs = [
            (plot_early_warnings,           "early_warnings.png",          []),
            (plot_benign_attack,            "benign_vs_attack.png",        []),
            (plot_test_peak_region,         "peak_region.png",             [first_attack]),
            (plot_Flow_Packets_s,           "flow_vs_seconds.png",         []),
            (plot_BytesPackets_s,           "bytes_vs_seconds.png",        []),
            (plot_dp_dt,                    "dp_dt.png",                   []),
            (plot_db_dt,                    "db_dt.png",                   []),
            (plot_d2p_dt2,                  "d2p_dt2.png",                 []),
            (plot_d2b_dt2,                  "d2b_dt2.png",                 []),
            (plot_alert_levels_separately,  None,                          []),   # multi‐file
            (generate_emergency_alerts,     "emergency_alerts.png",        []),
            (plot_All_alerts,               "all_alerts.png",              []),
            (plot_Flow_Packets_s_with_Attack_EWS, "flow_with_ews.png",     []),
            (plot_ews_confusion_matrix,     "ews_confusion.png",           [])
        ]

        urls = []
        for fn, fname, extra in plot_specs:
            try:
                if fn.__name__ == 'plot_alert_levels_separately':
                    # returns a list of filenames
                    level_files = fn(df.copy(), session_id, output_dir)
                    for lf in level_files:
                        urls.append(f"/plots/{session_id}/{lf}")
                else:
                    out = os.path.join(output_dir, fname)
                    fn(df.copy(), session_id, out, *extra)
                    urls.append(f"/plots/{session_id}/{fname}")
                    print(f"Generated plot: {fname}")
            except Exception as e:
                print(f"[!] Failed {fn.__name__}: {e}")
                traceback.print_exc()

        # 6) Return both the DataFrame & the list of URLs
        print(f"Successfully generated {len(urls)} plot URLs")
        return df, urls, first_attack, attack_idxs.tolist()
    except Exception as e:
        print(f"Failed to process file: {e}")
        traceback.print_exc()
        raise

def process_live_data(data_chunk, session_id):
    """Process a chunk of live captured data"""
    global output_dir
    
    # Convert data to DataFrame
    df = pd.DataFrame(data_chunk)
    
    # Skip if no data
    if df.empty:
        print("No data to process")
        return None, [], -1, []
    
    # Create session directory if not exists
    if output_dir is None:
        output_dir = os.path.join(app.config['PLOT_FOLDER'], session_id)
        os.makedirs(output_dir, exist_ok=True)
    
    try:
        # Print DataFrame column names to debug
        print(f"Processing dataframe with columns: {df.columns.tolist()}")
        
        # Standardize column names to match the expected format
        # Map the live capture field names to the names expected by the processing functions
        column_mappings = {
            'flow_packets_s': 'flow_packets_per_sec',
            'flow_bytes_s': 'flow_bytes_per_sec',
            'Flow_packets_s': 'flow_packets_per_sec',
            'Flow_bytes_s': 'flow_bytes_per_sec'
        }
        
        # Apply column rename for any columns that exist
        rename_dict = {}
        for src, dst in column_mappings.items():
            if src in df.columns:
                rename_dict[src] = dst
        
        if rename_dict:
            df.rename(columns=rename_dict, inplace=True)
            print(f"Renamed columns: {rename_dict}")
        
        # Apply processing steps
        print("1. Cleaning dataframe...")
        df = clean_dataframe(df)
        
        print("2. Sorting by timestamp...")
        df = sort_by_timestamp(df)
        
        print("3. Grouping and assigning seconds...")
        df = group_by_timestamp_and_assign_seconds_df(df)
        
        print("4. Processing flow data...")
        df = process_flow_df(df)
        
        print("5. Computing statistics...")
        df = compute_statistics_with_warning(df)
        
        # Rename for consistency in the JSON/table
        df.rename(columns={
            'Timestamp': 'Seconds',
            'Flow_packets_per_sec': 'Flow Packets/s',
            'Flow_bytes_per_sec': 'Flow Bytes/s'
        }, inplace=True)
        
        # Locate attack indices
        attack_idxs = np.where(df['Label'] != 'BENIGN')[0]
        first_attack = int(attack_idxs[0]) if len(attack_idxs) else -1
        
        print(f"Found {len(attack_idxs)} attack packets, first at index {first_attack}")
        
        # Generate all 17 plots exactly like process_file does
        plot_specs = [
            (plot_early_warnings,           "early_warnings.png",          []),
            (plot_benign_attack,            "benign_vs_attack.png",        []),
            (plot_test_peak_region,         "peak_region.png",             [first_attack]),
            (plot_Flow_Packets_s,           "flow_vs_seconds.png",         []),
            (plot_BytesPackets_s,           "bytes_vs_seconds.png",        []),
            (plot_dp_dt,                    "dp_dt.png",                   []),
            (plot_db_dt,                    "db_dt.png",                   []),
            (plot_d2p_dt2,                  "d2p_dt2.png",                 []),
            (plot_d2b_dt2,                  "d2b_dt2.png",                 []),
            (plot_alert_levels_separately,  None,                          []),   # multi‐file
            (generate_emergency_alerts,     "emergency_alerts.png",        []),
            (plot_All_alerts,               "all_alerts.png",              []),
            (plot_Flow_Packets_s_with_Attack_EWS, "flow_with_ews.png",     []),
            (plot_ews_confusion_matrix,     "ews_confusion.png",           [])
        ]

        urls = []
        for fn, fname, extra in plot_specs:
            try:
                if fn.__name__ == 'plot_alert_levels_separately':
                    # returns a list of filenames
                    level_files = fn(df.copy(), session_id, output_dir)
                    for lf in level_files:
                        urls.append(f"/plots/{session_id}/{lf}")
                else:
                    out = os.path.join(output_dir, fname)
                    fn(df.copy(), session_id, out, *extra)
                    urls.append(f"/plots/{session_id}/{fname}")
                    print(f"Generated plot: {fname}")
            except Exception as e:
                print(f"[!] Failed {fn.__name__}: {e}")
                traceback.print_exc()

        return df, urls, first_attack, attack_idxs.tolist()
    
    except Exception as e:
        # Print the full error for debugging
        import traceback
        print(f"[!] Error processing live data: {str(e)}")
        traceback.print_exc()
        return None, [], -1, []

def capture_packets():
    """Capture network packets using Scapy or simulate data if capture tools aren't available"""
    global live_capture_active, captured_data, last_processed_time
    
    try:
        # Try to check for winpcap/npcap installation
        from scapy.arch import get_windows_if_list
        has_winpcap = True
        
        # Get interfaces to see if we can capture
        interfaces = get_windows_if_list()
        if not interfaces:
            print("No network interfaces detected or WinPcap/Npcap not installed properly")
            has_winpcap = False
            raise ImportError("No usable network interfaces found")
            
    except (ImportError, RuntimeError):
        # If scapy fails to import or no interfaces available, use simulation
        has_winpcap = False
        print("WinPcap/Npcap not installed or properly configured. Using simulated data instead.")
    
    # If we have winpcap, try to use scapy for capture
    if has_winpcap:
        try:
            from scapy.all import sniff, IP, TCP, UDP
            
            def packet_callback(packet):
                if not live_capture_active:
                    return
                    
                if IP in packet:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                    
                    # Use enhanced detector for labeling
                    flow_type = detector.detect_attack_type(packet)
                    
                    # Extract packet features
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    protocol = packet[IP].proto
                    
                    # Calculate features based on protocol
                    if TCP in packet:
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport
                        flags = packet[TCP].flags
                        
                        # Some heuristic to identify potential attacks (just for demo)
                        if flags == 'S' and src_port < 1024:
                            flow_type = "PORT_SCAN"
                        
                    elif UDP in packet:
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                    else:
                        src_port = 0
                        dst_port = 0
                    
                    # Calculate length for packets and bytes per second
                    packet_length = len(packet)
                    
                    # Simplified data for demonstration
                    packet_data = {
                        "Timestamp": timestamp,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "flow_packets_s": 1,  # Will be aggregated later
                        "flow_bytes_s": packet_length,
                        "Label": flow_type
                    }
                    
                    # Add to captured data
                    captured_data.append(packet_data)
                    
                    # Process data more frequently
                    last_processed_time = time.time()
                    
                    # Save every 20 packets
                    if len(captured_data) % 20 == 0:
                        try:
                            csv_path = os.path.join(app.config['UPLOAD_FOLDER'], f"live_capture_{session_id}.csv")
                            pd.DataFrame(captured_data).to_csv(csv_path, index=False)
                            print(f"✅ Saved {len(captured_data)} packets to {csv_path}")
                        except Exception as e:
                            print(f"❌ Failed to save capture data: {str(e)}")
            
            try:
                # Try to start capturing with L3 sockets instead of L2
                print("Starting packet capture with L3 socket")
                from scapy.config import conf
                # Use layer 3 socket to avoid the winpcap requirement
                conf.use_pcap = False
                conf.L2listen = None
                conf.use_bpf = False
                sniff(prn=packet_callback, store=0, filter="ip")
            except Exception as e:
                print(f"Packet capture failed: {str(e)}. Falling back to simulated data.")
                has_winpcap = False  # Fall back to simulation
        except Exception as e:
            print(f"Error setting up packet capture: {str(e)}. Using simulated data instead.")
            has_winpcap = False
    
    # If we can't use scapy or it failed, use simulated data
    if not has_winpcap:
        print("Using simulated network traffic data")
        import random
        
        # Generate simulated packet data
        packet_count = 0
        start_time = datetime.now()
        
        # Create data with the same structure as CSV uploads for consistency
        print("Creating simulated data with consistent column structure")
        
        while live_capture_active:
            current_time = datetime.now()
            time_diff = (current_time - start_time).total_seconds()
            timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S.%f")
            
            # Generate more attack packets as time progresses for better demonstration
            attack_probability = min(0.4, 0.05 + (time_diff / 60) * 0.2)  # Increase attack probability over time
            flow_type = "BENIGN" if random.random() > attack_probability else random.choice(["DOS", "PORT_SCAN", "DDoS"])
            
            # Generate more realistic traffic patterns
            packet_length = random.randint(60, 1500)  # Typical packet sizes
            packets_per_second = random.randint(1, 10)  # Packets per second varies
            
            # Structure matching CSV upload format for consistent processing
            packet_data = {
                "Timestamp": timestamp,
                "src_ip": "192.168.0." + str(random.randint(1, 254)),
                "dst_ip": "10.0.0." + str(random.randint(1, 254)),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.randint(1, 1024),
                "protocol": random.choice([6, 17, 1]),  # TCP, UDP, ICMP
                "flow_packets_s": packets_per_second,
                "flow_bytes_s": packet_length * packets_per_second,
                "Label": flow_type
            }
            
            captured_data.append(packet_data)
            packet_count += 1
            
            # Save data periodically
            if packet_count % 20 == 0:
                try:
                    csv_path = os.path.join(app.config['UPLOAD_FOLDER'], f"live_capture_{session_id}.csv")
                    # Convert to DataFrame and save
                    df = pd.DataFrame(captured_data)
                    df.to_csv(csv_path, index=False)
                    
                    if packet_count == 20:
                        print(f"✅ Sample data structure: {packet_data}")
                        print(f"✅ DataFrame columns: {df.columns.tolist()}")
                    
                    if packet_count % 100 == 0:
                        print(f"✅ Saved {len(captured_data)} simulated packets to {csv_path}")
                        
                except Exception as e:
                    print(f"❌ Failed to save capture data: {str(e)}")
                    print(f"Data structure causing error: {type(captured_data)}")
                    traceback.print_exc()
            
            # Generate data faster for better visualization
            time.sleep(0.05)  # 20 packets per second

@app.route('/start-capture', methods=['POST'])
def start_capture():
    """Start live network capture"""
    global live_capture_active, capture_thread, captured_data, session_id, output_dir, last_processed_time
    
    if live_capture_active:
        return jsonify(error="Capture already running"), 400
    
    # Reset global variables
    live_capture_active = True
    captured_data = []
    session_id = str(uuid.uuid4())
    output_dir = None
    last_processed_time = time.time()
    
    print(f"Starting new capture session: {session_id}")
    
    # Clean up any existing plot files for this session (in case of restart)
    plot_dir = os.path.join(app.config['PLOT_FOLDER'], session_id)
    if os.path.exists(plot_dir):
        import shutil
        try:
            shutil.rmtree(plot_dir)
            print(f"Cleaned up existing plot directory: {plot_dir}")
        except Exception as e:
            print(f"Failed to clean up plot directory: {e}")
    
    # Create directories if they don't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Determine if we're likely to use simulation mode
    simulation_mode = False
    try:
        from scapy.arch import get_windows_if_list
        interfaces = get_windows_if_list()
        if not interfaces:
            simulation_mode = True
    except (ImportError, RuntimeError):
        simulation_mode = True
    
    # Start capture in a separate thread
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.daemon = True
    capture_thread.start()
    
    print(f"Capture started in {'simulation' if simulation_mode else 'real traffic'} mode")
    
    return jsonify(
        message="Live capture started",
        session_id=session_id,
        simulation_mode=simulation_mode
    ), 200

@app.route('/stop-capture', methods=['POST'])
def stop_capture():
    """Stop live network capture"""
    global live_capture_active, capture_thread, captured_data, session_id
    
    print(f"Stopping capture for session: {session_id}")
    
    # If not active, return an informative error but with a 200 status
    # This helps clients handle the situation more gracefully
    if not live_capture_active:
        return jsonify(
            message="No capture running - already stopped",
            success=False,
            records_captured=len(captured_data) if captured_data else 0,
            session_id=session_id
        ), 200
    
    # Set the flag to false to stop the capture thread
    live_capture_active = False
    
    # Wait for capture thread to terminate (with timeout)
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=2.0)
    
    # Save captured data to CSV for reference
    records_captured = 0
    if captured_data:
        records_captured = len(captured_data)
        csv_path = os.path.join(app.config['UPLOAD_FOLDER'], f"live_capture_{session_id}.csv")
        try:
            # Ensure the data has the expected columns for processing
            df = pd.DataFrame(captured_data)
            
            # Log the data structure
            print(f"Captured data columns: {df.columns.tolist()}")
            print(f"Captured data shape: {df.shape}")
            print(f"First few records:\n{df.head(2)}")
            
            # Save to CSV
            df.to_csv(csv_path, index=False)
            print(f"✅ Saved {records_captured} packets to {csv_path}")
        except Exception as e:
            print(f"❌ Error saving capture data: {str(e)}")
            traceback.print_exc()
    
    if records_captured == 0:
        print("❌ No packets were captured during the session")
    
    return jsonify(
        message="Live capture stopped",
        success=True,
        records_captured=records_captured,
        session_id=session_id
    ), 200

@app.route('/live-data', methods=['GET'])
def get_live_data():
    """Get the latest processed live data"""
    global captured_data, session_id, last_processed_time
    
    if not live_capture_active:
        # Return a more informative response when no capture is running
        return jsonify(
            error="No capture running",
            message="Start a capture session first",
            status="inactive",
            data=[]
        ), 200  # Use 200 status for better client handling
    
    if not captured_data:
        return jsonify(
            message="No data captured yet",
            status="capturing",
            data=[],
            capture_time=0,
            total_records=0
        ), 200
    
    # Calculate elapsed time from first packet - this will always work
    try:
        start_time = datetime.strptime(captured_data[0]["Timestamp"], "%Y-%m-%d %H:%M:%S.%f")
        capture_time = int((datetime.now() - start_time).total_seconds())
    except Exception as e:
        print(f"Error calculating time: {e}")
        capture_time = int(time.time() - last_processed_time)
    
    # ALWAYS include raw data (limited to avoid overwhelming the response)
    raw_data = [{'timestamp': p['Timestamp'], 
                 'src_ip': p['src_ip'], 
                 'dst_ip': p['dst_ip'],
                 'protocol': p['protocol'],
                 'bytes': p['flow_bytes_s'],
                 'label': p['Label']} 
                 for p in captured_data[-100:]]  # Last 100 packets
    
    try:
        # Make a copy to avoid race conditions
        data_to_process = captured_data.copy()
        
        # Try to process the data
        df, plot_urls, first_attack_idx, attack_indices = process_live_data(data_to_process, session_id)
        
        # If processing succeeds, return full results
        if df is not None and not df.empty:
            # Convert DataFrame to dict for JSON
            cleaned_json = df.to_dict(orient='records')
            
            # Extract key metrics for frontend visualization
            plot_data = {
                'first_attack_idx': first_attack_idx,
                'attack_indices': attack_indices,
                'ews_alerts': {
                    'level1': df[df['EWS'] == 1].index.tolist(),
                    'level2': df[df['EWS'] == 2].index.tolist(),
                    'level3': df[df['EWS'] == 3].index.tolist(),
                    'level4': df[df['EWS'] == 4].index.tolist(),
                },
                'high_alerts': df[df['EWS'] == 4].head(3).to_dict(orient='records')
            }
            
            # Save periodically
            if len(captured_data) % 50 == 0:
                try:
                    csv_path = os.path.join(app.config['UPLOAD_FOLDER'], f"live_capture_{session_id}.csv")
                    pd.DataFrame(captured_data).to_csv(csv_path, index=False)
                    print(f"✅ Saved {len(captured_data)} packets to {csv_path}")
                except Exception as e:
                    print(f"❌ Failed to save capture data: {str(e)}")
            
            # Return both processed data and raw data
            return jsonify(
                message="Live data processed",
                status="active",
                session_id=session_id,
                plots=plot_urls,
                cleaned_df=cleaned_json,
                plot_data=plot_data,
                total_records=len(captured_data),
                capture_time=capture_time,
                data=raw_data,  # Always include raw data
                processing_successful=True
            ), 200
    except Exception as e:
        import traceback
        print(f"Error processing live data: {e}")
        traceback.print_exc()
    
    # If we get here, processing failed - return just the raw data
    return jsonify(
        message="Processing data... (raw data available)",
        status="processing_raw",
        session_id=session_id,
        total_records=len(captured_data),
        capture_time=capture_time,
        data=raw_data,
        plots=[],
        cleaned_df=[],
        processing_successful=False
    ), 200

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify(error="No file"), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify(error="Empty filename"), 400

    session_id = str(uuid.uuid4())
    csv_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{session_id}.csv")
    file.save(csv_path)

    try:
        df, plot_urls, first_attack_idx, attack_indices = process_file(csv_path, session_id)
        cleaned_json = df.to_dict(orient='records')

        # Extract key metrics needed for frontend visualization
        plot_data = {
            'first_attack_idx': first_attack_idx,
            'attack_indices': attack_indices,
            'ews_alerts': {
                'level1': df[df['EWS'] == 1].index.tolist(),
                'level2': df[df['EWS'] == 2].index.tolist(),
                'level3': df[df['EWS'] == 3].index.tolist(),
                'level4': df[df['EWS'] == 4].index.tolist(),
            },
            'high_alerts': df[df['EWS'] == 4].head(3).to_dict(orient='records')
        }

        # <-- key change here: use keyword args or quoted keys
        return jsonify(
            message     = "File processed successfully",
            session_id  = session_id,
            plots       = plot_urls,
            cleaned_df  = cleaned_json,
            plot_data   = plot_data
        ), 200

    except Exception as e:
        # print full traceback to your console
        traceback.print_exc()
        return jsonify(error=str(e)), 500

@app.route('/plots/<path:filename>')
def serve_plot(filename):
    return send_from_directory(app.config['PLOT_FOLDER'], filename)

@app.route('/process-capture/<session_id>', methods=['GET'])
def process_capture(session_id):
    """Process a completed live capture session"""
    print(f"Processing capture for session: {session_id}")
    
    # Find the capture file
    csv_path = os.path.join(app.config['UPLOAD_FOLDER'], f"live_capture_{session_id}.csv")
    
    if not os.path.exists(csv_path):
        print(f"❌ Capture file not found: {csv_path}")
        return jsonify(error=f"No capture file found for session {session_id}"), 404
    
    try:
        # Read the raw CSV file to verify it has data
        try:
            raw_df = pd.read_csv(csv_path)
            if raw_df.empty:
                print(f"❌ Capture file is empty: {csv_path}")
                return jsonify(error="Capture file is empty"), 400
                
            print(f"✅ Found {len(raw_df)} records in capture file")
            print(f"Columns in raw file: {raw_df.columns.tolist()}")
        except Exception as e:
            print(f"❌ Error reading capture file: {str(e)}")
            return jsonify(error=f"Error reading capture file: {str(e)}"), 500
            
        # Process the file like a normal upload
        df, plot_urls, first_attack_idx, attack_indices = process_file(csv_path, session_id)
        
        # Debug derivative columns
        derivative_cols = ['dp/dt', 'db/dt', 'd2p/dt2', 'd2b/dt2']
        missing_cols = [col for col in derivative_cols if col not in df.columns]
        if missing_cols:
            print(f"⚠️ Missing derivative columns: {missing_cols}")
        else:
            print(f"✅ All derivative columns found")
            print(f"Sample derivative data:\n{df[derivative_cols].head(3)}")
        
        # Convert DataFrame to dict for JSON
        print(f"Processed data columns: {df.columns.tolist()}")
        cleaned_json = df.to_dict(orient='records')

        # Extract key metrics for frontend visualization
        plot_data = {
            'first_attack_idx': first_attack_idx,
            'attack_indices': attack_indices,
            'ews_alerts': {
                'level1': df[df['EWS'] == 1].index.tolist(),
                'level2': df[df['EWS'] == 2].index.tolist(),
                'level3': df[df['EWS'] == 3].index.tolist(),
                'level4': df[df['EWS'] == 4].index.tolist(),
            },
            'high_alerts': df[df['EWS'] == 4].head(3).to_dict(orient='records')
        }

        # Create the response data in the same format as upload endpoint
        response_data = {
            "message": "Capture processed successfully",
            "session_id": session_id,
            "plots": plot_urls,
            "cleaned_df": cleaned_json,
            "plot_data": plot_data,
            "total_records": len(df)
        }
        
        # Debug the response data structure
        print(f"✅ Successfully processed capture data with {len(df)} records and {len(plot_urls)} plots")
        print(f"Plot URLs: {plot_urls[:3]}...")
        print(f"Sample processed data: {cleaned_json[:2] if cleaned_json else []}")
        
        return jsonify(response_data), 200

    except Exception as e:
        traceback.print_exc()
        print(f"❌ Error processing capture: {str(e)}")
        return jsonify(error=str(e)), 500

@app.route('/download-plots/<session_id>', methods=['GET'])
def download_plots(session_id):
    """Download all plots for a session as a zip file"""
    import zipfile
    from io import BytesIO
    
    plots_dir = os.path.join(app.config['PLOT_FOLDER'], session_id)
    
    if not os.path.exists(plots_dir):
        return jsonify(error=f"No plots found for session {session_id}"), 404
    
    # Create a memory file for the zip
    memory_file = BytesIO()
    
    # Create a zip file in memory
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(plots_dir):
            for file in files:
                # Add each file to the zip with a flat structure
                file_path = os.path.join(root, file)
                arcname = file  # Use just the filename without the path
                zf.write(file_path, arcname)
    
    # Reset the file pointer
    memory_file.seek(0)
    
    # Create a timestamp for the filename
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    
    # Return the zip file as a download
    return Response(
        memory_file.getvalue(),
        mimetype='application/zip',
        headers={
            'Content-Disposition': f'attachment; filename=network_analysis_plots_{timestamp}.zip'
        }
    )

@app.route('/download-data/<session_id>', methods=['GET'])
def download_data(session_id):
    """Download the captured data as a CSV file"""
    # Check if this is a live capture or an uploaded file
    live_capture_path = os.path.join(app.config['UPLOAD_FOLDER'], f"live_capture_{session_id}.csv")
    uploaded_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{session_id}.csv")
    
    # Determine which file exists
    if os.path.exists(live_capture_path):
        file_path = live_capture_path
        file_type = "live_capture"
    elif os.path.exists(uploaded_file_path):
        file_path = uploaded_file_path
        file_type = "uploaded"
    else:
        return jsonify(error=f"No data file found for session {session_id}"), 404
    
    # Create a timestamp for the filename
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    
    # Return the file as a download
    return send_from_directory(
        directory=os.path.dirname(file_path),
        path=os.path.basename(file_path),
        as_attachment=True,
        download_name=f"network_traffic_data_{file_type}_{timestamp}.csv"
    )

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
