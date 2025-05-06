#!/usr/bin/env python3
"""
OpenSnitch Smart Policy with Reinforcement Learning - Main Entry Point
This script initializes and runs the OpenSnitch RL agent.
"""

import os
import sys
import time
import signal
import logging
import argparse
from typing import Optional

# Import the RL Agent module
# Assuming the code is in a file called opensnitch_rl.py
from utils.Agent import OpenSnitchPolicy, simulate_connections
from utils.Sim import OpenSnitchPlayback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("opensnitch_rl_main.log"), logging.StreamHandler()],
)
logger = logging.getLogger("opensnitch_rl_main")


def main():
    """
    Main entry point for Weems - the adaptive network traffic filter
    """
    print("OpenSnitch Smart Policy with Reinforcement Learning")
    print("=" * 60)

    # Parse command line arguments
    import argparse

    parser = argparse.ArgumentParser(description="Weems")

    parser.add_argument("--model", type=str, help="Path to pre-trained model file")
    parser.add_argument(
        "--simulate", type=int, default=0, help="Run simulation with N connections"
    )
    parser.add_argument(
        "--no-training", action="store_true", help="Disable training mode"
    )
    parser.add_argument(
        "--random-training", action="store_true", help="Train with random input"
    )
    parser.add_argument(
        "--no-auto-rules",
        action="store_true",
        help="Disable automatic rule application",
    )
    args = parser.parse_args()

    # Create policy
    if args.model is None:
        policy = OpenSnitchPolicy()
    else:
        policy = OpenSnitchPolicy(model_path=args.model)

    # Configure policy based on arguments
    if args.no_training:
        policy.training_mode = False
    if args.no_auto_rules:
        policy.auto_apply_rules = False

    # Try to load existing state
    policy.load_state()

    # Start training thread in background
    if policy.training_mode:
        policy.start_training_thread()

    try:
        if args.simulate > 0:
            # Run simulation
            print(f"Running simulation with {args.simulate} connections...")
            simulate_connections(policy, args.simulate)
            # osp = OpenSnitchPlayback(
            #    db_path='data/opensnitch.sqlite.dne',
            #    limit=args.simulate,
            #    callback=policy.handle_connection
            # )
            # osp.simulate()
        else:
            print("TODO: real implementation. Sleeping forever. Press Ctrl+C to exit.")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Save final state
        policy.save_state()

        # Stop training thread
        policy.stop_training_thread()

    print("Done.")


if __name__ == "__main__":
    main()
