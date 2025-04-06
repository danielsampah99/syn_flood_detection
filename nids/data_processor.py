"""
Data Processor for SYN Flood Detection

This script processes pcap (packet capture) files to extract features for detecting SYN flood attacks.
It analyzes both normal and attack traffic to prepare data for machine learning model training.

Key features extracted:
- Time delta between packets (crucial for SYN flood detection)
- SYN flag presence and ratios
- Packet count statistics
- Destination port information
"""

import argparse
import logging
import os
from collections import defaultdict
from typing import Any, DefaultDict, Dict, Optional, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from scapy.all import IP, TCP, rdpcap

# Logging to track progress and errors
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger('DataProcessor')


def extract_features_from_pcap(pcap_file: str, label: int = 0) -> pd.DataFrame:
    """
    Extract network traffic features from a pcap file for SYN flood detection.

    This function:
    1. Reads a pcap file using scapy
    2. Filters for TCP packets
    3. Extracts time-based and TCP flag-based features
    4. Calculates statistics for each source IP address

    Args:
        pcap_file: Path to the pcap file containing network traffic
        label: 0 for normal traffic, 1 for attack traffic

    Returns:
        DataFrame containing extracted features with one row per source IP
    """
    logger.info(f"Processing {pcap_file}...")

    try:
        # Load all packets from the pcap file
        # rdpcap returns a list of packet objects that we can analyze
        packets = rdpcap(pcap_file)
        logger.info(f"Loaded {len(packets)} packets from {pcap_file}")
    except Exception as e:
        logger.error(f"Failed to read pcap file: {e}")
        return pd.DataFrame()  # Return empty DataFrame on error

    # Filter for TCP packets that also have IP headers
    # This is important because SYN flood attacks specifically target TCP
    tcp_packets = [pkt for pkt in packets if TCP in pkt and IP in pkt]
    logger.info(f"Found {len(tcp_packets)} TCP packets")

    if len(tcp_packets) == 0:
        logger.warning("No TCP packets found in the capture file")
        return pd.DataFrame()

    # Tracking statistics for each source IP
    ip_tracker: DefaultDict[str, Dict[str, Any]] = defaultdict(lambda: {
        'packets': [], 'times': [], 'syn_count': 0, 'total_count': 0, 'dst_ports': set()
    })

    # Process each TCP packet to extract features
    for packet in tcp_packets:
        # Extract basic packet information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        timestamp = float(packet.time)

        # Update tracking information for this source IP
        tracker = ip_tracker[src_ip]
        tracker['packets'].append(packet)
        tracker['times'].append(timestamp)
        tracker['total_count'] += 1
        tracker['dst_ports'].add(dst_port)

        # Check if this is a SYN packet
        # SYN flag is the key indicator for SYN flood attacks
        if (flags & 0x02):  # Bitwise AND to check if SYN flag is set
            tracker['syn_count'] += 1

    # Generate feature rows for each source IP
    feature_rows = []

    for src_ip, tracker in ip_tracker.items():
        # Skip IPs with too few packets: manual limit of 3
        if tracker['total_count'] < 3:
            continue

        # Calculate time deltas between consecutive packets from this IP
        times = sorted(tracker['times'])
        time_deltas = [times[i] - times[i-1] for i in range(1, len(times))]

        # Statistical features from the time deltas
        if len(time_deltas) > 0:
            avg_time_delta = np.mean(time_deltas)  # Average time between packets
            std_time_delta = np.std(time_deltas) if len(time_deltas) > 1 else 0  # Variation in timing
            min_time_delta = min(time_deltas)  # Fastest packet succession
            max_time_delta = max(time_deltas)  # Slowest packet succession
        else:
            avg_time_delta = std_time_delta = min_time_delta = max_time_delta = 0

        # Calculate SYN ratio (percentage of packets that are SYN packets)
        # In SYN floods, this ratio is typically very high
        syn_ratio = tracker['syn_count'] / tracker['total_count']

        # Feature dictionary for this source IP
        feature_row = {
            'src_ip': src_ip,                           # Source IP address
            'packet_count': tracker['total_count'],     # Total packets from this IP
            'syn_count': tracker['syn_count'],          # Number of SYN packets
            'syn_ratio': syn_ratio,                     # Ratio of SYN to total packets
            'unique_dst_ports': len(tracker['dst_ports']),  # Number of unique ports targeted
            'avg_time_delta': avg_time_delta,           # Average time between packets
            'std_time_delta': std_time_delta,           # Standard deviation of time between packets
            'min_time_delta': min_time_delta,           # Minimum time between packets
            'max_time_delta': max_time_delta,           # Maximum time between packets
            'label': label                              # 0 for normal, 1 for attack
        }

        feature_rows.append(feature_row)

    # Convert the list of feature dictionaries to a pandas DataFrame
    df = pd.DataFrame(feature_rows)
    logger.info(f"Extracted {len(df)} feature rows")

    return df


def visualize_features(df: pd.DataFrame, output_dir: str) -> None:
    """
    Create visualizations to analyze and understand the extracted features.

    These visualizations help us:
    1. See how normal and attack traffic differ
    2. Identify the most important features for detection
    3. Understand patterns in the data

    Args:
        df: DataFrame containing the extracted features
        output_dir: Directory to save visualization files
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Set up descriptive labels for plots
    label_names = {0: 'Normal', 1: 'Attack'}
    df['traffic_type'] = df['label'].map(label_names)

    # VISUALIZATION 1: SYN RATIO DISTRIBUTION
    plt.figure(figsize=(10, 6))
    sns.histplot(data=df, x='syn_ratio', hue='traffic_type', bins=20, kde=True)
    plt.title('Distribution of SYN Ratio')
    plt.xlabel('SYN Ratio (SYN packets / Total packets)')
    plt.ylabel('Count')
    plt.savefig(os.path.join(output_dir, 'syn_ratio_distribution.png'))

    # VISUALIZATION 2: TIME DELTA DISTRIBUTION
    # Shows the distribution of time between packets
    # Attacks have very consistent adn small time deltas
    plt.figure(figsize=(10, 6))
    sns.histplot(data=df, x='avg_time_delta', hue='traffic_type', bins=20, kde=True, log_scale=True)
    plt.title('Distribution of Average Time Delta Between Packets')
    plt.xlabel('Average Time Delta (seconds)')
    plt.ylabel('Count')
    plt.savefig(os.path.join(output_dir, 'time_delta_distribution.png'))

    # VISUALIZATION 3: TIME DELTA BOXPLOT
    # Shows the range and quartiles of time deltas by traffic type
    plt.figure(figsize=(10, 6))
    sns.boxplot(data=df, x='traffic_type', y='avg_time_delta')
    plt.title('Time Delta by Traffic Type')
    plt.ylabel('Average Time Delta (seconds)')
    plt.yscale('log')  # Log scale helps visualize wide ranges
    plt.savefig(os.path.join(output_dir, 'time_delta_boxplot.png'))

    # VISUALIZATION 4: SYN RATIO VS PACKET COUNT
    # Shows relationship between SYN ratio and number of packets
    plt.figure(figsize=(10, 8))
    sns.scatterplot(
        data=df,
        x='packet_count',
        y='syn_ratio',
        hue='traffic_type',
        size='unique_dst_ports',
        sizes=(20, 200)
    )
    plt.title('SYN Ratio vs Packet Count')
    plt.xlabel('Packet Count')
    plt.ylabel('SYN Ratio')
    plt.xscale('log')  # Log scale for better visualization of packet counts
    plt.savefig(os.path.join(output_dir, 'syn_ratio_vs_packet_count.png'))

    # VISUALIZATION 5: FEATURE CORRELATION HEATMAP
    # Shows how different features correlate with each other
    plt.figure(figsize=(12, 10))
    feature_cols = [
        'packet_count', 'syn_count', 'syn_ratio', 'unique_dst_ports',
        'avg_time_delta', 'std_time_delta', 'min_time_delta', 'max_time_delta'
    ]
    corr = df[feature_cols].corr()
    sns.heatmap(corr, annot=True, cmap='coolwarm', fmt='.2f')
    plt.title('Feature Correlation Heatmap')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'feature_correlation.png'))

    logger.info(f"Saved feature visualizations to {output_dir}")


def process_captures(
    normal_dir: str,
    attack_dir: str,
    output_dir: str
) -> Tuple[Optional[pd.DataFrame], Optional[pd.DataFrame], Optional[pd.DataFrame]]:
    """
    Process normal and attack captures and generate feature datasets.

    This function:
    1. Finds all pcap files in the specified directories
    2. Extracts features from each file
    3. Combines the features into datasets
    4. Saves the datasets for model training
    5. Creates visualizations

    Args:
        normal_dir: Directory containing normal traffic pcap files
        attack_dir: Directory containing attack traffic pcap files
        output_dir: Directory to save processed data and visualizations

    Returns:
        Tuple of DataFrames: (normal_df, attack_df, combined_df)
        Any of these may be None if processing fails
    """
    # Create output directories
    os.makedirs(output_dir, exist_ok=True)
    viz_dir = os.path.join(output_dir, 'visualizations')
    os.makedirs(viz_dir, exist_ok=True)

    # Find all pcap files in the normal traffic directory
    normal_files = [os.path.join(normal_dir, f) for f in os.listdir(normal_dir)
                   if f.endswith('.pcap')]

    if not normal_files:
        logger.error(f"No pcap files found in {normal_dir}")
        return None, None, None

    logger.info(f"Found {len(normal_files)} normal traffic pcap files")

    # Process each normal pcap file and combine into one DataFrame
    normal_dfs = []
    for pcap_file in normal_files:
        df = extract_features_from_pcap(pcap_file, label=0)  # Label 0 = normal
        if not df.empty:
            normal_dfs.append(df)

    # Combine all normal traffic DataFrames
    normal_df = pd.concat(normal_dfs, ignore_index=True) if normal_dfs else pd.DataFrame()

    if normal_df.empty:
        logger.error("Failed to extract features from normal traffic")
        return None, None, None

    # Find all pcap files in the attack traffic directory
    attack_files = [os.path.join(attack_dir, f) for f in os.listdir(attack_dir)
                   if f.endswith('.pcap')]

    if not attack_files:
        logger.error(f"No pcap files found in {attack_dir}")
        return normal_df, None, None

    logger.info(f"Found {len(attack_files)} attack traffic pcap files")

    # Process each attack pcap file and combine into one DataFrame
    attack_dfs = []
    for pcap_file in attack_files:
        df = extract_features_from_pcap(pcap_file, label=1)  # Label 1 = attack
        if not df.empty:
            attack_dfs.append(df)

    # Combine all attack traffic DataFrames
    attack_df = pd.concat(attack_dfs, ignore_index=True) if attack_dfs else pd.DataFrame()

    if attack_df.empty:
        logger.error("Failed to extract features from attack traffic")
        return normal_df, None, None

    # Combine normal and attack DataFrames for the final dataset
    combined_df = pd.concat([normal_df, attack_df], ignore_index=True)

    # Save all datasets to CSV files for later use
    normal_df.to_csv(os.path.join(output_dir, 'normal_features.csv'), index=False)
    attack_df.to_csv(os.path.join(output_dir, 'attack_features.csv'), index=False)
    combined_df.to_csv(os.path.join(output_dir, 'combined_features.csv'), index=False)

    logger.info(f"Saved processed data to {output_dir}")

    # Create visualizations to understand the data
    visualize_features(combined_df, viz_dir)

    return normal_df, attack_df, combined_df


def main() -> None:
    """
    Main function to parse command line arguments and run the data processing pipeline.
    """
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Process pcap files for SYN flood detection')
    parser.add_argument('--normal-dir', type=str, default='data/normal',
                        help='Directory containing normal traffic pcap files')
    parser.add_argument('--attack-dir', type=str, default='data/attack',
                        help='Directory containing attack traffic pcap files')
    parser.add_argument('--output-dir', type=str, default='data/processed',
                        help='Directory to save processed data')

    args = parser.parse_args()

    # Get absolute paths to directories
    script_dir = os.path.dirname(os.path.abspath(__file__))
    normal_dir = os.path.join(script_dir, args.normal_dir)
    attack_dir = os.path.join(script_dir, args.attack_dir)
    output_dir = os.path.join(script_dir, args.output_dir)

    # Process the captures
    normal_df, attack_df, combined_df = process_captures(normal_dir, attack_dir, output_dir)

    # Print statistics about the processed data
    if combined_df is not None and not combined_df.empty:
        logger.info("\n--- Dataset Statistics ---")
        logger.info(f"Normal traffic: {len(normal_df)} samples")
        logger.info(f"Attack traffic: {len(attack_df)} samples")
        logger.info(f"Combined dataset: {len(combined_df)} samples")

        # Print summary statistics for the features
        logger.info("\n--- Feature Summary ---")
        logger.info("\nNormal Traffic:")
        logger.info(normal_df.describe())

        logger.info("\nAttack Traffic:")
        logger.info(attack_df.describe())

        logger.info("\nProcessing complete! Data is ready for model training.")


# Entry point of the script
if __name__ == "__main__":
    main()
