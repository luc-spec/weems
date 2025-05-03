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
from opensnitch_rl import OpenSnitchRLAgent, OpenSnitchConnection

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("opensnitch_rl_main.log"), logging.StreamHandler()],
)
logger = logging.getLogger("opensnitch_rl_main")


class OpenSnitchSimulator:
    """
    Simulates OpenSnitch connections for testing purposes.
    In a real implementation, this would integrate with OpenSnitch's API.
    """

    def __init__(self):
        self.common_connections = [
            # Web browser connecting to websites
            OpenSnitchConnection(
                process_path="/usr/bin/firefox",
                pid=1000,
                dst_ip="142.250.185.78",
                dst_host="www.google.com",
                dst_port=443,
                protocol="tcp",
                user_id=1000,
            ),
            # Email client
            OpenSnitchConnection(
                process_path="/usr/bin/thunderbird",
                pid=1001,
                dst_ip="104.47.56.33",
                dst_host="outlook.office365.com",
                dst_port=993,
                protocol="tcp",
                user_id=1000,
            ),
            # System update
            OpenSnitchConnection(
                process_path="/usr/bin/apt",
                pid=1002,
                dst_ip="91.189.91.38",
                dst_host="archive.ubuntu.com",
                dst_port=80,
                protocol="tcp",
                user_id=0,
            ),
            # Suspicious connection (example)
            OpenSnitchConnection(
                process_path="/tmp/suspicious_app",
                pid=1003,
                dst_ip="203.0.113.100",  # Example IP in documentation range
                dst_host="malware-server.example",
                dst_port=4444,  # Common malware port
                protocol="tcp",
                user_id=1000,
            ),
        ]

    def get_random_connection(self):
        """Return a random connection from the list of common connections"""
        import random

        return random.choice(self.common_connections)


def simulate_user_feedback():
    """Simulate a user's feedback on a decision"""
    import random

    return random.choice([True, False])


def main(model_path: Optional[str] = None, simulation_mode: bool = False):
    """
    Main entry point for the OpenSnitch RL Agent

    Args:
        model_path: Path to a pre-trained model file (optional)
        simulation_mode: Whether to run in simulation mode for testing
    """
    logger.info("Starting OpenSnitch RL Agent")

    # Initialize the agent
    agent = OpenSnitchRLAgent(model_path=model_path)

    if simulation_mode:
        logger.info("Running in simulation mode")
        simulator = OpenSnitchSimulator()

        try:
            # Run simulation loop
            for i in range(1000):  # Simulate 1000 connections
                connection = simulator.get_random_connection()
                logger.info(
                    f"Simulation {i+1}: {connection.process_path} -> {connection.dst_host}:{connection.dst_port}"
                )

                # Get decision from agent
                action, rule = agent.decide(connection)

                # Simulate user feedback (for learning)
                feedback = simulate_user_feedback()

                # Provide feedback to agent
                reward = agent.reward_function.calculate_reward(
                    agent.feature_extractor.extract(connection), action, None, feedback
                )

                # Add to memory for training
                state = agent.feature_extractor.extract(connection)
                agent.memory.add(state, action, reward, state, False)

                # Update exploration strategy
                state_hash = hash(tuple(state)) % 1000000
                state_hash = f"{connection.process_path}_{state_hash}"
                agent.exploration.update(state_hash, action, reward)

                # Train periodically
                if i % 10 == 0:
                    loss = agent.train()
                    if loss is not None:
                        logger.info(f"Training loss: {loss}")

                # Sleep to simulate time passing
                time.sleep(0.1)

        except KeyboardInterrupt:
            logger.info("Simulation interrupted")

        # Save the model after simulation
        save_path = "opensnitch_rl_model.pth"
        agent.save_model(save_path)
        logger.info(f"Model saved to {save_path}")

    else:
        # In a real implementation, this would integrate with OpenSnitch's events
        logger.info("Real mode not implemented - need OpenSnitch API integration")
        logger.info("To test functionality, run with --simulation flag")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OpenSnitch RL Agent")
    parser.add_argument("--model", type=str, help="Path to pre-trained model file")
    parser.add_argument(
        "--simulation", action="store_true", help="Run in simulation mode"
    )

    args = parser.parse_args()

    # Register signal handler for clean exit
    def signal_handler(sig, frame):
        logger.info("Exiting OpenSnitch RL Agent")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Run main function
    main(model_path=args.model, simulation_mode=args.simulation)
