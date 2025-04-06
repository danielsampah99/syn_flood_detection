"""
Network Intrusion Detection System (NIDS) for SYN Flood Protection

This script implements a real-time SYN flood detector that monitors network traffic,
detects attack patterns using a trained machine learning model, and automatically
blocks attackers using IPtables rules.

Features:
- Real-time packet capture and analysis
- Feature extraction from network packets
- ML-based attack detection
- Automatic IPtables rule generation
- Scheduled unblocking of IPs after specified duration
- Comprehensive logging and statistics
"""

import argparse
import ipaddress
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, DefaultDict, Dict, List, Optional, Set, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from scapy.all import IP, TCP, sniff


class SynFloodDetector:
    """
    SYN Flood Detector class that monitors network traffic and blocks attackers.

    This class:
    1. Captures network packets in real-time
    2. Extracts relevant features
    3. Uses a trained ML model to detect attacks
    4. Blocks attackers using IPtables
    5. Unblocks IPs after a specified duration
    """

    def __init__(
        self,
        model_path: str,
        interface: str,
        time_window: int = 5,
        block_duration: int = 300,
        threshold: float = 0.7,
        stats_interval: int = 10,
        log_file: Optional[str] = None,
        is_kmeans: bool = False
    ) -> None:
        """
        Initialize the SYN flood detector.

        Args:
            model_path: Path to the trained ML model file
            interface: Network interface to monitor
            time_window: Time window in seconds for feature calculation
            block_duration: Duration in seconds to block attackers
            threshold: Probability/confidence threshold for attack classification
            stats_interval: Interval in seconds to print statistics
            log_file: Path to log file (None for console logging only)
            is_kmeans: Whether the model is K-means or Random Forest
        """
        # Setup logging
        self.setup_logging(log_file)

        # Configuration
        self.interface = interface
        self.time_window = time_window
        self.block_duration = block_duration
        self.threshold = threshold
        self.stats_interval = stats_interval
        self.is_kmeans = is_kmeans

        # Initialize data structures
        self.packet_stats: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)  # Track packets by source IP
        self.blocked_ips: Set[str] = set()  # Currently blocked IPs
        self.unblock_timers: Dict[str, threading.Timer] = {}  # Timers for unblocking IPs

        # State tracking
        self.last_stats_time = time.time()
        self.last_cleanup_time = time.time()
        self.running = True

        # Statistics counters
        self.total_packets = 0
        self.syn_packets = 0
        self.attack_detections = 0

        # Load the model and supporting components
        try:
            self.logger.info(f"Loading model from {model_path}")
            self.model = joblib.load(model_path)

            # If using K-means, also load the scaler and cluster attack mapping
            if self.is_kmeans:
                model_dir = os.path.dirname(model_path)
                scaler_path = os.path.join(model_dir, 'kmeans_scaler.pkl')

                self.logger.info(f"Loading K-means scaler from {scaler_path}")
                self.scaler = joblib.load(scaler_path)

                # Try to load cluster attack likelihood mapping
                try:
                    attack_likelihood_path = os.path.join(model_dir, 'cluster_attack_likelihood.txt')
                    self.cluster_attack_likelihood = self._load_cluster_attack_likelihood(attack_likelihood_path)
                except:
                    # Default to empty mapping if file not found
                    self.cluster_attack_likelihood = {}
                    self.logger.warning("Cluster attack likelihood mapping not found")

            self.logger.info("Model loaded successfully")
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            sys.exit(1)

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        self.logger.info("SYN Flood Detector initialized")

    def _load_cluster_attack_likelihood(self, file_path: str) -> Dict[int, float]:
        """
        Load the mapping from cluster ID to attack likelihood.

        Args:
            file_path: Path to the cluster attack likelihood file

        Returns:
            Dictionary mapping cluster IDs to attack probabilities
        """
        likelihood_map = {}

        try:
            with open(file_path, 'r') as f:
                # Skip header line
                next(f)

                for line in f:
                    if ":" in line:
                        parts = line.split(":")
                        cluster_str = parts[0].strip().replace("Cluster ", "")
                        likelihood_str = parts[1].strip()

                        cluster_id = int(cluster_str)
                        likelihood = float(likelihood_str)

                        likelihood_map[cluster_id] = likelihood

            self.logger.info(f"Loaded attack likelihood mapping for {len(likelihood_map)} clusters")
        except Exception as e:
            self.logger.error(f"Failed to load cluster attack likelihood mapping: {e}")

        return likelihood_map

    def setup_logging(self, log_file: Optional[str] = None) -> None:
        """
        Set up logging configuration.

        Args:
            log_file: Path to log file (None for console logging only)
        """
        self.logger = logging.getLogger("SynFloodDetector")
        self.logger.setLevel(logging.INFO)

        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # Create file handler if log file specified
        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def signal_handler(self, sig: int, frame: Any) -> None:
        """
        Handle termination signals for graceful shutdown.

        Args:
            sig: Signal number
            frame: Current stack frame
        """
        self.logger.info(f"Received signal {sig}, shutting down...")
        self.running = False

        # Cancel all pending unblock timers
        for ip, timer in self.unblock_timers.items():
            timer.cancel()

        self.logger.info("Shutdown complete")
        sys.exit(0)

    def extract_features(self, src_ip: str) -> Optional[pd.DataFrame]:
        """
        Extract features from collected packets for a specific source IP.

        This function calculates the same features used during model training:
        - Time deltas between packets
        - SYN flag statistics
        - Packet counts

        Args:
            src_ip: Source IP to extract features for

        Returns:
            DataFrame with features or None if not enough data
        """
        packets = self.packet_stats[src_ip]

        # Need enough packets to make a reliable decision
        if len(packets) < 3:
            return None

        # Calculate basic packet statistics
        syn_count = sum(1 for p in packets if p['is_syn'])
        packet_count = len(packets)
        syn_ratio = syn_count / packet_count if packet_count > 0 else 0

        # Extract timestamps and calculate time deltas
        times = [p['time'] for p in packets]
        time_deltas = [times[i] - times[i-1] for i in range(1, len(times))]

        if not time_deltas:
            return None

        # Calculate time delta statistics
        avg_time_delta = np.mean(time_deltas)
        std_time_delta = np.std(time_deltas) if len(time_deltas) > 1 else 0
        min_time_delta = min(time_deltas)
        max_time_delta = max(time_deltas)

        # Count unique destination ports
        dst_ports = set(p['dst_port'] for p in packets)

        # Create feature DataFrame (matching the format used in training)
        features = {
            'packet_count': packet_count,
            'syn_count': syn_count,
            'syn_ratio': syn_ratio,
            'unique_dst_ports': len(dst_ports),
            'avg_time_delta': avg_time_delta,
            'std_time_delta': std_time_delta,
            'min_time_delta': min_time_delta,
            'max_time_delta': max_time_delta
        }

        # Convert to DataFrame
        feature_df = pd.DataFrame([features])

        return feature_df

    def is_attack_random_forest(self, features: pd.DataFrame) -> Tuple[bool, float]:
        """
        Determine if features indicate an attack using the Random Forest model.

        Args:
            features: DataFrame with extracted features

        Returns:
            Tuple of (is_attack, confidence)
        """
        try:
            # Get prediction probability (confidence)
            proba = self.model.predict_proba(features)[0]
            attack_confidence = proba[1]  # Probability of the attack class
            is_attack = attack_confidence > self.threshold

            return is_attack, attack_confidence
        except:
            # Fallback to simple prediction if probabilities not available
            prediction = self.model.predict(features)[0]
            is_attack = prediction == 1
            confidence = 1.0 if is_attack else 0.0

            return is_attack, confidence

    def is_attack_kmeans(self, features: pd.DataFrame) -> Tuple[bool, float]:
        """
        Determine if features indicate an attack using the K-means model.

        In K-means approach:
        1. We extract only the time delta feature
        2. We scale it using the saved scaler
        3. We predict the cluster ID
        4. We use the cluster's attack likelihood to determine if it's an attack

        Args:
            features: DataFrame with extracted features

        Returns:
            Tuple of (is_attack, confidence)
        """
        try:
            # Extract and scale the time delta feature
            X = features[['avg_time_delta']]
            X_scaled = self.scaler.transform(X)

            # Predict cluster
            cluster = self.model.predict(X_scaled)[0]

            # Get attack likelihood for this cluster
            attack_confidence = self.cluster_attack_likelihood.get(cluster, 0.0)
            is_attack = attack_confidence > self.threshold

            return is_attack, attack_confidence
        except Exception as e:
            self.logger.error(f"Error in K-means prediction: {e}")
            return False, 0.0

    def is_attack(self, features: Optional[pd.DataFrame]) -> Tuple[bool, float]:
        """
        Determine if features indicate an attack using the appropriate model.

        Args:
            features: DataFrame with extracted features

        Returns:
            Tuple of (is_attack, confidence)
        """
        if features is None:
            return False, 0.0

        if self.is_kmeans:
            return self.is_attack_kmeans(features)
        else:
            return self.is_attack_random_forest(features)

    def block_ip(self, ip: str) -> None:
        """
        Block an IP address using IPtables.

        This function:
        1. Creates an IPtables rule to drop all traffic from the IP
        2. Schedules the IP to be unblocked after block_duration
        3. Logs the action

        Args:
            ip: IP address to block
        """
        # Skip if already blocked
        if ip in self.blocked_ips:
            return

        try:
            # Validate IP address to prevent command injection
            ipaddress.ip_address(ip)
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip}")
            return

        self.logger.warning(f"🛑 Blocking attack from {ip}")

        # Create IPtables rule
        cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"

        try:
            # Execute the command
            subprocess.run(cmd, shell=True, check=True, capture_output=True)

            # Update our tracking
            self.blocked_ips.add(ip)
            self.logger.info(f"Successfully blocked {ip} with IPtables rule")

            # Schedule unblocking
            self.schedule_unblock(ip)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block {ip} with IPtables: {e}")
            if e.stderr:
                self.logger.error(f"Error output: {e.stderr.decode('utf-8')}")

    def unblock_ip(self, ip: str) -> None:
        """
        Unblock an IP address by removing the IPtables rule.

        Args:
            ip: IP address to unblock
        """
        if ip not in self.blocked_ips:
            return

        self.logger.info(f"Unblocking {ip} (block duration expired)")

        # Create IPtables command to remove the block rule
        cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"

        try:
            # Execute the command
            subprocess.run(cmd, shell=True, check=True, capture_output=True)

            # Update our tracking
            self.blocked_ips.remove(ip)

            # Remove from unblock timers if present
            if ip in self.unblock_timers:
                del self.unblock_timers[ip]

            self.logger.info(f"Successfully unblocked {ip}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to unblock {ip}: {e}")
            if e.stderr:
                self.logger.error(f"Error output: {e.stderr.decode('utf-8')}")

    def schedule_unblock(self, ip: str) -> None:
        """
        Schedule an IP to be unblocked after block_duration seconds.

        Args:
            ip: IP address to schedule for unblocking
        """
        # Cancel any existing timer for this IP
        if ip in self.unblock_timers:
            self.unblock_timers[ip].cancel()

        # Create new timer
        timer = threading.Timer(self.block_duration, self.unblock_ip, args=[ip])
        timer.daemon = True  # Allow the timer to be terminated with the program
        timer.start()

        # Store the timer reference
        self.unblock_timers[ip] = timer

        self.logger.info(f"Scheduled {ip} to be unblocked after {self.block_duration} seconds")

    def packet_callback(self, packet: Any) -> None:
        """
        Process a captured packet to extract features and detect attacks.

        This function is called for each packet captured by scapy.
        It:
        1. Extracts relevant packet information
        2. Updates statistics for the source IP
        3. Periodically checks for attacks
        4. Blocks attackers when detected

        Args:
            packet: Scapy packet object
        """
        current_time = time.time()

        # Process only TCP/IP packets (SYN flood is a TCP attack)
        if TCP in packet and IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport

            # Check if this is a SYN packet (flag = 0x02)
            is_syn = (packet[TCP].flags & 0x02) == 0x02

            # Update global statistics
            self.total_packets += 1
            if is_syn:
                self.syn_packets += 1

            # Skip processing for already blocked IPs
            if src_ip in self.blocked_ips:
                return

            # Skip localhost traffic if requested (not implemented yet)
            # if self.skip_localhost and (src_ip.startswith('127.') or dst_ip.startswith('127.')):
            #     return

            # Store packet info
            self.packet_stats[src_ip].append({
                'time': current_time,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'is_syn': is_syn
            })

            # Periodically clean up old packets
            if current_time - self.last_cleanup_time > 10:
                self.cleanup_old_packets(current_time)
                self.last_cleanup_time = current_time

            # Print statistics periodically
            if current_time - self.last_stats_time > self.stats_interval:
                self.print_statistics()
                self.last_stats_time = current_time

            # Check for attack pattern from this source IP
            features = self.extract_features(src_ip)
            is_attack, confidence = self.is_attack(features)

            if is_attack:
                self.attack_detections += 1
                self.logger.warning(
                    f"Attack detected from {src_ip} with confidence {confidence:.4f} "
                    f"(threshold: {self.threshold})"
                )
                self.block_ip(src_ip)

    def cleanup_old_packets(self, current_time: float) -> None:
        """
        Remove packets older than time_window from statistics.

        Args:
            current_time: Current timestamp
        """
        cutoff_time = current_time - self.time_window
        removed_count = 0

        # Remove old packets from each source IP's list
        for ip in list(self.packet_stats.keys()):
            old_length = len(self.packet_stats[ip])

            # Keep only recent packets
            self.packet_stats[ip] = [
                p for p in self.packet_stats[ip]
                if p['time'] >= cutoff_time
            ]

            # Track how many were removed
            removed_count += old_length - len(self.packet_stats[ip])

            # Remove empty entries
            if not self.packet_stats[ip]:
                del self.packet_stats[ip]

        self.logger.debug(
            f"Cleaned up {removed_count} old packets. "
            f"Tracking {len(self.packet_stats)} source IPs."
        )

    def print_statistics(self) -> None:
        """
        Print operational statistics about packet processing and attacks.
        """
        tracked_ips = len(self.packet_stats)
        blocked_ips = len(self.blocked_ips)
        syn_percentage = (self.syn_packets / self.total_packets * 100) if self.total_packets > 0 else 0

        self.logger.info(
            f"Stats: {self.total_packets} packets ({self.syn_packets} SYN = {syn_percentage:.1f}%), "
            f"{tracked_ips} IPs tracked, {blocked_ips} IPs blocked, "
            f"{self.attack_detections} attacks detected"
        )

        # If any IPs are blocked, list them
        if blocked_ips > 0:
            self.logger.info(f"Blocked IPs: {', '.join(self.blocked_ips)}")

    def start(self) -> None:
        """
        Start monitoring network traffic for SYN flood attacks.

        This function:
        1. Begins packet capture on the specified interface
        2. Processes each packet to detect attacks
        3. Continues until interruption or error
        """
        self.logger.info(f"🔍 Starting SYN flood detection on interface {self.interface}")
        self.logger.info(f"Using {'K-means' if self.is_kmeans else 'Random Forest'} model")
        self.logger.info(f"Feature window: {self.time_window} seconds, Block duration: {self.block_duration} seconds")
        self.logger.info(f"Detection threshold: {self.threshold}")
        self.logger.info(f"Press Ctrl+C to stop")

        # Display current IPtables rules
        self.display_iptables_rules()

        # Reset statistics
        self.total_packets = 0
        self.syn_packets = 0
        self.attack_detections = 0
        self.last_stats_time = time.time()

        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except KeyboardInterrupt:
            self.logger.info("\nStopping SYN flood detection (keyboard interrupt)")
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")
        finally:
            # Print final statistics
            self.print_statistics()

            # Display final IPtables rules
            self.display_iptables_rules()

    def display_iptables_rules(self) -> None:
        """
        Display current IPtables rules.
        """
        self.logger.info("Current IPtables rules:")

        try:
            result = subprocess.run(
                "sudo iptables -L INPUT -n",
                shell=True,
                check=True,
                capture_output=True,
                text=True
            )
            self.logger.info("\n" + result.stdout)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get IPtables rules: {e}")


def main() -> None:
    """
    Parse command line arguments and start the SYN flood detector.
    """
    parser = argparse.ArgumentParser(description='SYN Flood Detection System')
    parser.add_argument('--model', required=True, help='Path to trained model file')
    parser.add_argument('--interface', required=True, help='Network interface to monitor')
    parser.add_argument('--window', type=int, default=5, help='Time window in seconds for detection')
    parser.add_argument('--block-duration', type=int, default=300, help='Duration to block attackers in seconds')
    parser.add_argument('--threshold', type=float, default=0.7, help='Detection threshold (0.0-1.0)')
    parser.add_argument('--stats-interval', type=int, default=10, help='Interval to print statistics in seconds')
    parser.add_argument('--log-file', type=str, help='Path to log file (optional)')
    parser.add_argument('--kmeans', action='store_true', help='Use K-means model instead of Random Forest')

    args = parser.parse_args()

    # Create the detector
    detector = SynFloodDetector(
        model_path=args.model,
        interface=args.interface,
        time_window=args.window,
        block_duration=args.block_duration,
        threshold=args.threshold,
        stats_interval=args.stats_interval,
        log_file=args.log_file,
        is_kmeans=args.kmeans
    )

    # Start monitoring
    detector.start()


if __name__ == "__main__":
    main()
