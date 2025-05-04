#!/usr/bin/env python3
"""
Network Log Analyzer

This script analyzes network connection logs from a security tool (like OpenSnitch)
and generates statistics and visualizations about connection patterns, blocking rules,
and potential security issues.
"""

import re
import sys
import json
import argparse
from datetime import datetime
from collections import Counter, defaultdict
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path


class NetworkLogAnalyzer:
    def __init__(self, log_file_path):
        """Initialize the log analyzer with the path to the log file."""
        self.log_file_path = log_file_path
        self.logs = []
        self.connections = []
        self.rules = []
        self.df = None
        self.loaded = False

    def load_logs(self):
        """Load and parse the log file."""
        print(f"Loading logs from {self.log_file_path}...")

        # Regular expressions for parsing log lines
        connection_pattern = re.compile(
            r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (\w+) - (\w+) - "
            r"Connection (\d+)/(\d+): ([\w/.-]+) → ([\w.-]+):(\d+) \| Action: (.+)"
        )

        rule_pattern = re.compile(
            r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (\w+) - (\w+) - "
            r"Generated rule: (.+)"
        )

        warning_pattern = re.compile(
            r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (\w+) - (\w+) - "
            r"Allowing connection to potentially malicious site: (.+)"
        )

        try:
            with open(self.log_file_path, "r") as file:
                for line in file:
                    line = line.strip()

                    # Parse connection lines
                    conn_match = connection_pattern.match(line)
                    if conn_match:
                        (
                            timestamp,
                            component,
                            level,
                            conn_num,
                            total_conn,
                            process,
                            dest_host,
                            dest_port,
                            action,
                        ) = conn_match.groups()
                        self.connections.append(
                            {
                                "timestamp": timestamp,
                                "component": component,
                                "level": level,
                                "connection_number": int(conn_num),
                                "total_connections": int(total_conn),
                                "process": process,
                                "destination_host": dest_host,
                                "destination_port": int(dest_port),
                                "action": action,
                            }
                        )
                        continue

                    # Parse rule generation lines
                    rule_match = rule_pattern.match(line)
                    if rule_match:
                        timestamp, component, level, rule_json = rule_match.groups()
                        try:
                            rule_data = eval(
                                rule_json
                            )  # Note: using eval for simplicity, but in production should use safer method
                            rule_data["timestamp"] = timestamp
                            rule_data["component"] = component
                            rule_data["level"] = level
                            self.rules.append(rule_data)
                        except Exception as e:
                            print(f"Error parsing rule JSON: {e}")
                        continue

                    # Add all lines to raw logs
                    self.logs.append(line)

            # Create a DataFrame from connections
            if self.connections:
                self.df = pd.DataFrame(self.connections)
                self.df["timestamp"] = pd.to_datetime(self.df["timestamp"])

                # Convert the 'action' column to actionType and duration
                self.df["actionType"] = self.df["action"].str.split(" ").str[0]
                self.df["duration"] = self.df["action"].str.split(" ").str[1:]
                self.df["duration"] = self.df["duration"].apply(
                    lambda x: " ".join(x) if x else None
                )

                print(
                    f"Loaded {len(self.connections)} connection records and {len(self.rules)} rules."
                )
                self.loaded = True
            else:
                print("No connection records found in the log file.")

        except Exception as e:
            print(f"Error loading logs: {e}")

    def generate_basic_stats(self):
        """Generate basic statistics about the connections."""
        if not self.loaded:
            print("Please load logs first.")
            return

        print("\n=== Basic Statistics ===")

        # Connection counts
        total_connections = len(self.connections)
        print(f"Total connections: {total_connections}")

        # Count by action type
        action_counts = self.df["actionType"].value_counts()
        print("\nAction counts:")
        for action, count in action_counts.items():
            print(f"  {action}: {count} ({count/total_connections*100:.1f}%)")

        # Top destinations
        top_destinations = self.df["destination_host"].value_counts().head(10)
        print("\nTop 10 destination hosts:")
        for host, count in top_destinations.items():
            print(f"  {host}: {count} ({count/total_connections*100:.1f}%)")

        # Top processes
        top_processes = self.df["process"].value_counts().head(10)
        print("\nTop 10 processes:")
        for process, count in top_processes.items():
            print(f"  {process}: {count} ({count/total_connections*100:.1f}%)")

        # Top ports
        top_ports = self.df["destination_port"].value_counts().head(10)
        print("\nTop 10 destination ports:")
        for port, count in top_ports.items():
            print(f"  {port}: {count} ({count/total_connections*100:.1f}%)")

    def plot_connections_over_time(self, output_path=None):
        """Plot the number of connections over time."""
        if not self.loaded:
            print("Please load logs first.")
            return

        plt.figure(figsize=(12, 6))

        # Resample by minute and count connections
        connections_by_time = self.df.set_index("timestamp").resample("1min").size()

        plt.plot(connections_by_time.index, connections_by_time.values)
        plt.title("Connections Over Time")
        plt.xlabel("Time")
        plt.ylabel("Number of Connections")
        plt.grid(True)
        plt.tight_layout()

        if output_path:
            plt.savefig(output_path)
            print(f"Saved connection time plot to {output_path}")
        else:
            plt.show()

        plt.close()

    def plot_action_distribution(self, output_path=None):
        """Plot the distribution of actions (allow/block)."""
        if not self.loaded:
            print("Please load logs first.")
            return

        plt.figure(figsize=(10, 6))

        actions = self.df["actionType"].value_counts()
        colors = ["green" if action == "Allow" else "red" for action in actions.index]

        ax = actions.plot(kind="bar", color=colors)
        plt.title("Distribution of Connection Actions")
        plt.xlabel("Action")
        plt.ylabel("Count")
        plt.xticks(rotation=0)

        # Add percentage labels
        total = actions.sum()
        for i, count in enumerate(actions):
            percentage = count / total * 100
            ax.text(i, count, f"{percentage:.1f}%", ha="center", va="bottom")

        plt.tight_layout()

        if output_path:
            plt.savefig(output_path)
            print(f"Saved action distribution plot to {output_path}")
        else:
            plt.show()

        plt.close()

    def plot_process_host_heatmap(self, top_n=10, output_path=None):
        """Create a heatmap showing which processes connect to which hosts."""
        if not self.loaded:
            print("Please load logs first.")
            return

        # Get top processes and hosts
        top_processes = self.df["process"].value_counts().head(top_n).index.tolist()
        top_hosts = (
            self.df["destination_host"].value_counts().head(top_n).index.tolist()
        )

        # Filter data to only include top processes and hosts
        filtered_df = self.df[
            self.df["process"].isin(top_processes)
            & self.df["destination_host"].isin(top_hosts)
        ]

        # Create a pivot table for the heatmap
        pivot_table = pd.pivot_table(
            filtered_df,
            index="process",
            columns="destination_host",
            values="connection_number",
            aggfunc="count",
            fill_value=0,
        )

        plt.figure(figsize=(12, 8))
        sns.heatmap(pivot_table, annot=True, fmt="d", cmap="YlGnBu")
        plt.title(f"Connection Frequency Between Top {top_n} Processes and Hosts")
        plt.ylabel("Process")
        plt.xlabel("Destination Host")
        plt.tight_layout()

        if output_path:
            plt.savefig(output_path)
            print(f"Saved process-host heatmap to {output_path}")
        else:
            plt.show()

        plt.close()

    def plot_blocked_vs_allowed_by_process(self, top_n=10, output_path=None):
        """Plot blocked vs allowed connections for top processes."""
        if not self.loaded:
            print("Please load logs first.")
            return

        # Get top processes by total connections
        top_processes = self.df["process"].value_counts().head(top_n).index.tolist()

        # Filter data to only include top processes
        filtered_df = self.df[self.df["process"].isin(top_processes)]

        # Group by process and action
        grouped = (
            filtered_df.groupby(["process", "actionType"]).size().unstack(fill_value=0)
        )

        # Ensure 'Allow' and 'Block' columns exist
        for action in ["Allow", "Block"]:
            if action not in grouped.columns:
                grouped[action] = 0

        # Sort by total connections
        grouped["Total"] = grouped.sum(axis=1)
        grouped.sort_values("Total", ascending=False, inplace=True)
        grouped.drop(columns=["Total"], inplace=True)

        plt.figure(figsize=(12, 8))
        grouped.plot(kind="barh", stacked=True, color=["green", "red"])
        plt.title(f"Blocked vs Allowed Connections by Top {top_n} Processes")
        plt.xlabel("Number of Connections")
        plt.ylabel("Process")
        plt.grid(True, axis="x")
        plt.legend(title="Action")
        plt.tight_layout()

        if output_path:
            plt.savefig(output_path)
            print(f"Saved blocked vs allowed plot to {output_path}")
        else:
            plt.show()

        plt.close()

    def plot_destination_port_distribution(self, top_n=10, output_path=None):
        """Plot the distribution of destination ports."""
        if not self.loaded:
            print("Please load logs first.")
            return

        plt.figure(figsize=(12, 6))

        port_counts = self.df["destination_port"].value_counts().head(top_n)
        port_counts.plot(kind="bar")
        plt.title(f"Top {top_n} Destination Ports")
        plt.xlabel("Port")
        plt.ylabel("Number of Connections")
        plt.xticks(rotation=45)
        plt.grid(True, axis="y")
        plt.tight_layout()

        if output_path:
            plt.savefig(output_path)
            print(f"Saved port distribution plot to {output_path}")
        else:
            plt.show()

        plt.close()

    def analyze_potentially_malicious_connections(self):
        """Analyze potentially malicious connections."""
        if not self.loaded:
            print("Please load logs first.")
            return

        # Look for warning patterns in the logs
        malicious_indicators = ["malware", "ads", "suspicious", "WARNING"]

        # Filter connections with potentially malicious destinations
        malicious_df = self.df[
            self.df["destination_host"].str.contains(
                "|".join(malicious_indicators), case=False
            )
        ]

        if len(malicious_df) > 0:
            print("\n=== Potentially Malicious Connections ===")
            print(f"Found {len(malicious_df)} potentially malicious connections.")

            # Group by destination host
            malicious_hosts = malicious_df["destination_host"].value_counts()
            print("\nMalicious destination hosts:")
            for host, count in malicious_hosts.items():
                print(f"  {host}: {count} connections")

            # Group by process
            malicious_processes = malicious_df["process"].value_counts()
            print("\nProcesses with malicious connections:")
            for process, count in malicious_processes.items():
                print(f"  {process}: {count} connections")

            # Action breakdown
            malicious_actions = malicious_df["actionType"].value_counts()
            print("\nActions taken for malicious connections:")
            for action, count in malicious_actions.items():
                print(f"  {action}: {count} ({count/len(malicious_df)*100:.1f}%)")
        else:
            print("\nNo potentially malicious connections found.")

    def export_to_csv(self, output_path):
        """Export the analyzed data to CSV."""
        if not self.loaded:
            print("Please load logs first.")
            return

        self.df.to_csv(output_path, index=False)
        print(f"Exported data to {output_path}")

    def generate_report(self, output_dir):
        """Generate a comprehensive report with statistics and visualizations."""
        if not self.loaded:
            print("Please load logs first.")
            return

        # Create output directory if it doesn't exist
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate basic stats
        self.generate_basic_stats()

        # Generate visualizations
        self.plot_connections_over_time(
            output_path=output_dir / "connections_over_time.png"
        )
        self.plot_action_distribution(
            output_path=output_dir / "action_distribution.png"
        )
        self.plot_process_host_heatmap(
            top_n=10, output_path=output_dir / "process_host_heatmap.png"
        )
        self.plot_blocked_vs_allowed_by_process(
            top_n=10, output_path=output_dir / "blocked_vs_allowed.png"
        )
        self.plot_destination_port_distribution(
            top_n=10, output_path=output_dir / "port_distribution.png"
        )

        # Analyze potentially malicious connections
        self.analyze_potentially_malicious_connections()

        # Export data to CSV
        self.export_to_csv(output_dir / "connections.csv")

        print(f"\nReport generated in {output_dir}")


def main():
    """Main function to parse arguments and run the analyzer."""
    parser = argparse.ArgumentParser(description="Analyze network security logs")
    parser.add_argument("log_file", help="Path to the log file")
    parser.add_argument(
        "--output",
        "-o",
        help="Output directory for the report",
        default=".weems/log_analysis_report",
    )
    parser.add_argument(
        "--export-only",
        action="store_true",
        help="Only export data to CSV without generating visualizations",
    )

    args = parser.parse_args()

    analyzer = NetworkLogAnalyzer(args.log_file)
    analyzer.load_logs()

    if args.export_only:
        analyzer.export_to_csv(f"{args.output}_connections.csv")
    else:
        analyzer.generate_report(args.output)


if __name__ == "__main__":
    main()
