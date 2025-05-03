#!/usr/bin/env python3
"""
OpenSnitch Smart Policy with Reinforcement Learning (Python Implementation)
This module implements an intelligent, adaptive policy for OpenSnitch firewall
using Deep Recurrent Q-Networks (DRQN) and POMDPs.
"""

import os
import sys
import uuid
import time
import json
import pickle
import logging
import numpy as np
import threading
from datetime import datetime
from collections import deque, namedtuple
from typing import List, Dict, Tuple, Optional, Any, Union

# Deep Learning imports
import torch
import torch.optim as optim
from torch.utils.tensorboard import SummaryWriter

# Local Imports
from DecisionStructure import Actions, Experience
from UI import AgenTUI
from OpensnitchInterface import OpenSnitchConnection, RuleGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(".weems/agent.log"), logging.StreamHandler()],
)
logger = logging.getLogger("agent")


class PrioritizedReplayBuffer:
    """Prioritized Experience Replay buffer for storing RL experiences"""

    def __init__(self, capacity: int, alpha: float = 0.6, beta: float = 0.4):
        self.capacity = capacity
        self.alpha = alpha  # How much prioritization to use (0=none, 1=full)
        self.beta = beta  # Importance sampling correction (0=none, 1=full)
        self.beta_increment = 0.001  # Beta annealing
        self.epsilon = 1e-5  # Small value to avoid zero priority

        self.buffer = []
        self.priorities = np.ones((capacity,), dtype=np.float32)
        self.position = 0
        self.size = 0

    def add(self, state, action, reward, next_state, done):
        """Add a new experience to the buffer"""
        experience = Experience(state, action, reward, next_state, done)

        # Find the max priority in buffer or use 1.0 if buffer is empty
        max_priority = self.priorities.max() if self.size > 0 else 1.0

        if self.size < self.capacity:
            self.buffer.append(experience)
            self.size += 1
        else:
            self.buffer[self.position] = experience

        # New experiences get max priority to ensure they're sampled at least once
        self.priorities[self.position] = max_priority
        self.position = (self.position + 1) % self.capacity

    def sample(self, batch_size: int) -> Tuple[List, List[int], torch.Tensor]:
        """Sample a batch of experiences based on priorities"""
        if self.size < batch_size:
            # If we don't have enough experiences, sample with replacement
            indices = np.random.choice(self.size, batch_size, replace=True)
        else:
            # Calculate sampling probabilities from priorities
            priorities = self.priorities[: self.size]
            probs = priorities**self.alpha
            probs /= probs.sum()

            # Sample based on priorities
            indices = np.random.choice(self.size, batch_size, replace=False, p=probs)

        # Calculate importance sampling weights
        weights = (self.size * probs[indices]) ** (-self.beta)
        weights /= weights.max()  # Normalize
        weights = torch.tensor(weights, dtype=torch.float32)

        # Increment beta for annealing
        self.beta = min(1.0, self.beta + self.beta_increment)

        # Return sampled experiences, indices (for priority update), and weights
        samples = [self.buffer[idx] for idx in indices]
        return samples, indices, weights

    def update_priorities(self, indices: List[int], priorities: np.ndarray):
        """Update priorities based on TD error"""
        for idx, priority in zip(indices, priorities):
            self.priorities[idx] = priority + self.epsilon

    def is_ready_for_training(self, min_samples: int = 1000) -> bool:
        """Check if we have enough experiences to start training"""
        return self.size >= min_samples

    def __len__(self) -> int:
        return self.size


class DRQN(torch.nn.Module):
    """Deep Recurrent Q-Network for sequential decision making with partial observability"""

    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 128):
        super(DRQN, self).__init__()

        self.state_dim = state_dim
        self.action_dim = action_dim
        self.hidden_dim = hidden_dim

        # Feature extraction layers
        self.feature_layers = torch.torch.nn.Sequential(
            torch.torch.nn.Linear(state_dim, 256),
            torch.torch.nn.ReLU(),
            torch.torch.nn.Linear(256, 256),
            torch.torch.nn.ReLU(),
        )

        # LSTM layer for temporal dependencies
        self.lstm = torch.torch.nn.LSTM(256, hidden_dim, batch_first=True)

        # Advantage stream (A)
        self.advantage = torch.torch.nn.Sequential(
            torch.torch.nn.Linear(hidden_dim, 128),
            torch.torch.nn.ReLU(),
            torch.torch.nn.Linear(128, action_dim),
        )

        # Value stream (V)
        self.value = torch.torch.nn.Sequential(
            torch.torch.nn.Linear(hidden_dim, 128),
            torch.torch.nn.ReLU(),
            torch.torch.nn.Linear(128, 1),
        )

    def forward(self, state, hidden_state=None):
        """
        Forward pass through the network

        Args:
            state: Tensor of shape (batch_size, sequence_length, state_dim)
            hidden_state: tuple of (h, c) with shape (1, batch_size, hidden_dim)

        Returns:
            q_values: Tensor of shape (batch_size, action_dim)
            next_hidden: tuple of (h, c) with shape (1, batch_size, hidden_dim)
        """
        batch_size = state.size(0)
        seq_length = state.size(1)

        # Process each time step through feature layers
        features = self.feature_layers(state.view(-1, self.state_dim))
        features = features.view(batch_size, seq_length, -1)

        # Process sequence through LSTM
        if hidden_state is None:
            lstm_out, next_hidden = self.lstm(features)
        else:
            lstm_out, next_hidden = self.lstm(features, hidden_state)

        # We only care about the last output for Q-values
        lstm_out = lstm_out[:, -1]

        # Dueling architecture
        advantage = self.advantage(lstm_out)
        value = self.value(lstm_out)

        # Combine value and advantage to get Q-values
        # Q(s,a) = V(s) + (A(s,a) - mean(A(s,a')))
        q_values = value + advantage - advantage.mean(dim=1, keepdim=True)

        return q_values, next_hidden

    def init_hidden(self, batch_size: int):
        """Initialize hidden state"""
        return (
            torch.zeros(1, batch_size, self.hidden_dim),
            torch.zeros(1, batch_size, self.hidden_dim),
        )


class FeatureExtractor:
    """Extracts relevant features from OpenSnitch connection data and system context"""

    def __init__(self):
        self.ip_cache = {}  # Cache for IP-related features
        self.domain_cache = {}  # Cache for domain-related features
        self.app_cache = {}  # Cache for application-related features

        # Define protocol mapping
        self.protocol_map = {"tcp": 0, "udp": 1, "icmp": 2, "igmp": 3, "ipv6": 4}

        # Load reputation data if available
        self.reputation_data = self._load_reputation_data()

    def _load_reputation_data(self) -> Dict:
        """Load domain and IP reputation data from file"""
        try:
            with open("reputation_data.json", "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning("Could not load reputation data, using empty dict")
            return {"domains": {}, "ips": {}}

    def extract(self, connection: OpenSnitchConnection) -> np.ndarray:
        """Extract features from a connection object"""
        # Basic connection features
        features = []

        # 1. Process features
        process_features = self._extract_process_features(
            connection.process_path, connection.pid
        )
        features.extend(process_features)

        # 2. Network features
        network_features = self._extract_network_features(
            connection.dst_ip,
            connection.dst_host,
            connection.dst_port,
            connection.protocol,
        )
        features.extend(network_features)

        # 3. User context features
        user_features = self._extract_user_features(connection.user_id)
        features.extend(user_features)

        # 4. Temporal features
        time_features = self._extract_time_features(connection.timestamp)
        features.extend(time_features)

        # 5. System context features
        system_features = self._extract_system_features()
        features.extend(system_features)

        # Convert to numpy array
        return np.array(features, dtype=np.float32)

    def _extract_process_features(self, process_path: str, pid: int) -> List[float]:
        """Extract features related to the process making the connection"""
        features = []

        # Process path hash (normalized to [0,1])
        path_hash = hash(process_path) % 1000000
        features.append(path_hash / 1000000.0)

        # Process age (if in cache)
        if process_path in self.app_cache:
            app_data = self.app_cache[process_path]
            # Time since first seen (days, normalized)
            time_known = (time.time() - app_data.get("first_seen", time.time())) / (
                86400 * 30
            )  # Normalize to ~30 days
            features.append(min(time_known, 1.0))

            # Previous connections count (normalized)
            prev_connections = min(app_data.get("connection_count", 0) / 1000, 1.0)
            features.append(prev_connections)

            # Previous blocks ratio
            if app_data.get("connection_count", 0) > 0:
                block_ratio = app_data.get("blocks", 0) / app_data.get(
                    "connection_count", 1
                )
            else:
                block_ratio = 0.0
            features.append(block_ratio)
        else:
            # New application
            self.app_cache[process_path] = {
                "first_seen": time.time(),
                "connection_count": 0,
                "blocks": 0,
            }
            features.extend([0.0, 0.0, 0.0])  # New app default features

        # Update connection count
        if process_path in self.app_cache:
            self.app_cache[process_path]["connection_count"] += 1

        # One-hot for system vs user application (rough heuristic)
        is_system_app = int("/usr/bin/" in process_path or "/usr/sbin/" in process_path)
        features.append(float(is_system_app))
        features.append(float(not is_system_app))

        return features

    def _extract_network_features(
        self, ip: str, host: str, port: int, protocol: str
    ) -> List[float]:
        """Extract features related to the network connection"""
        features = []

        # Port category (normalized)
        if port < 1024:
            port_category = 0.0  # Well-known
        elif port < 49152:
            port_category = 0.5  # Registered
        else:
            port_category = 1.0  # Dynamic/Private
        features.append(port_category)

        # Common service port one-hot encoding
        common_ports = {80: 0, 443: 1, 53: 2, 22: 3, 25: 4}
        port_features = [0.0] * len(common_ports)
        if port in common_ports:
            port_features[common_ports[port]] = 1.0
        features.extend(port_features)

        # Protocol one-hot encoding
        protocol_features = [0.0] * len(self.protocol_map)
        if protocol.lower() in self.protocol_map:
            protocol_features[self.protocol_map[protocol.lower()]] = 1.0
        features.extend(protocol_features)

        # Domain reputation (if available)
        domain_reputation = 0.5  # Default neutral reputation
        if host in self.reputation_data["domains"]:
            domain_reputation = self.reputation_data["domains"][host]
        features.append(domain_reputation)

        # IP reputation (if available)
        ip_reputation = 0.5  # Default neutral reputation
        if ip in self.reputation_data["ips"]:
            ip_reputation = self.reputation_data["ips"][ip]
        features.append(ip_reputation)

        # Domain category features could be added here
        # For simplicity, we're just adding placeholder values
        domain_category_features = [0.0] * 5  # Placeholder for categories
        features.extend(domain_category_features)

        return features

    def _extract_user_features(self, user_id: int) -> List[float]:
        """Extract features related to the user context"""
        features = []

        # Is root user
        is_root = float(user_id == 0)
        features.append(is_root)

        # Other user-specific features could be added here
        # Placeholder for now
        features.extend([0.0] * 2)

        return features

    def _extract_time_features(self, timestamp: float) -> List[float]:
        """Extract temporal features from timestamp"""
        features = []

        # Get current datetime
        dt = datetime.fromtimestamp(timestamp)

        # Hour of day (normalized to [0,1])
        hour = dt.hour / 23.0
        features.append(hour)

        # Day of week (normalized to [0,1])
        day = dt.weekday() / 6.0
        features.append(day)

        # Weekend vs weekday
        is_weekend = float(dt.weekday() >= 5)
        features.append(is_weekend)

        # Working hours (8am-6pm) vs non-working
        is_working_hours = float(8 <= dt.hour < 18)
        features.append(is_working_hours)

        return features

    def _extract_system_features(self) -> List[float]:
        """Extract features related to system context"""
        features = []

        # Network environment type (placeholder)
        # In a real implementation, this would detect home/work/public network
        network_type_features = [1.0, 0.0, 0.0]  # Home, Work, Public
        features.extend(network_type_features)

        # Battery status - on battery vs plugged in (placeholder)
        on_battery = 0.0  # Plugged in
        features.append(on_battery)

        # VPN active (placeholder)
        vpn_active = 0.0
        features.append(vpn_active)

        # System load (normalized)
        try:
            load_avg = (
                os.getloadavg()[0] / 4.0
            )  # Normalize by number of cores (assumed 4)
            load = min(load_avg, 1.0)
        except:
            load = 0.5  # Default if can't get load
        features.append(load)

        return features


class RewardFunction:
    """Calculate rewards for reinforcement learning based on actions and outcomes"""

    def __init__(self):
        self.reputation_threshold_malicious = 0.3
        self.reputation_threshold_legitimate = 0.7

        # Reward values
        self.allowed_malicious_penalty = -10.0
        self.blocked_legitimate_penalty = -1.0
        self.allowed_legitimate_reward = 1.0
        self.blocked_suspicious_reward = 0.5
        self.user_interruption_penalty = -0.2

    def calculate_reward(
        self,
        state: np.ndarray,
        action: int,
        next_state: Optional[np.ndarray] = None,
        user_feedback: Optional[bool] = None,
    ) -> float:
        """
        Calculate the reward for a state-action pair

        Args:
            state: The state features
            action: The action taken
            next_state: The resulting state (optional)
            user_feedback: User feedback if available (True=approve, False=disapprove)

        Returns:
            float: The calculated reward
        """
        # Extract reputation scores from state
        # (Assuming specific indices in the feature vector - in a real implementation,
        # this would be more robust)
        domain_reputation_idx = 15  # Example index
        domain_reputation = state[domain_reputation_idx]

        # If we have explicit user feedback, use it as primary signal
        if user_feedback is not None:
            if action in [Actions.ALLOW_ONCE, Actions.ALLOW_TEMP, Actions.ALLOW_PERM]:
                # User approved our allow decision
                return 2.0 if user_feedback else -5.0
            else:
                # User approved our block decision
                return 2.0 if not user_feedback else -5.0

        # Otherwise calculate based on action and reputation
        if action in [Actions.ALLOW_ONCE, Actions.ALLOW_TEMP, Actions.ALLOW_PERM]:
            # Allowed connection
            if domain_reputation < self.reputation_threshold_malicious:
                # Allowed something suspicious/malicious
                return self.allowed_malicious_penalty * (1 - domain_reputation) * 2
            else:
                # Allowed something legitimate
                return self.allowed_legitimate_reward * domain_reputation
        elif action in [Actions.BLOCK_ONCE, Actions.BLOCK_TEMP, Actions.BLOCK_PERM]:
            # Blocked connection
            if domain_reputation > self.reputation_threshold_legitimate:
                # Blocked something legitimate
                return self.blocked_legitimate_penalty * domain_reputation
            else:
                # Blocked something suspicious
                return self.blocked_suspicious_reward * (1 - domain_reputation)
        else:  # Asked user
            return self.user_interruption_penalty


class ThompsonSampling:
    """Thompson Sampling exploration strategy with Bayesian uncertainty"""

    def __init__(self, alpha: float = 1.0, beta: float = 1.0):
        self.alpha = alpha  # Prior parameter
        self.beta = beta  # Prior parameter
        self.action_counts = {}  # Dict to store counts for each state-action pair

    def select_action(
        self, q_values: torch.Tensor, state_hash: str, exploit_threshold: float = 0.95
    ) -> int:
        """
        Select action using Thompson sampling

        Args:
            q_values: Q-values for all actions
            state_hash: Hash representation of the state
            exploit_threshold: Probability threshold for exploitation

        Returns:
            int: Selected action index
        """
        n_actions = q_values.shape[0]

        # Get current action counts for this state
        if state_hash not in self.action_counts:
            self.action_counts[state_hash] = {
                a: {"success": self.alpha, "failure": self.beta}
                for a in range(n_actions)
            }

        # With some probability, exploit the best action
        if np.random.random() < exploit_threshold:
            return q_values.argmax().item()

        # Otherwise, sample from Beta distribution for each action
        samples = []
        for a in range(n_actions):
            counts = self.action_counts[state_hash][a]
            # Sample from Beta distribution
            sample = np.random.beta(counts["success"], counts["failure"])
            samples.append(sample)

        # Return action with highest sampled value
        return np.argmax(samples)

    def update(self, state_hash: str, action: int, reward: float):
        """
        Update action counts based on reward

        Args:
            state_hash: Hash representation of the state
            action: Action taken
            reward: Reward received
        """
        if state_hash not in self.action_counts:
            self.action_counts[state_hash] = {
                a: {"success": self.alpha, "failure": self.beta}
                for a in range(Actions.count())
            }

        # Positive reward increases success count, negative increases failure count
        if reward > 0:
            self.action_counts[state_hash][action]["success"] += abs(reward)
        else:
            self.action_counts[state_hash][action]["failure"] += abs(reward)


class StateHistoryTracker:
    """Track state history for recurrent learning"""

    def __init__(self, max_history: int = 10):
        self.max_history = max_history
        self.state_history = {}  # Dict to store state history for each application

    def add_state(self, app_id: str, state: np.ndarray):
        """Add a new state to the history"""
        if app_id not in self.state_history:
            self.state_history[app_id] = deque(maxlen=self.max_history)

        self.state_history[app_id].append(state)

    def get_sequence(self, app_id: str) -> np.ndarray:
        """Get state sequence for an application"""
        if app_id not in self.state_history:
            return np.zeros((1, 0), dtype=np.float32)

        # Convert deque to numpy array
        sequence = np.array(list(self.state_history[app_id]))
        return sequence

    def get_state_hash(self, app_id: str, state: np.ndarray) -> str:
        """Generate a hash for the current state"""
        # For simplicity, just hash the state vector
        # In a real implementation, we would use a more robust hashing method
        # that considers the relevant features for the decision
        state_hash = str(hash(state.tobytes()) % 100000)
        return f"{app_id}_{state_hash}"


class OpenSnitchPolicy:
    """Intelligent policy for OpenSnitch using reinforcement learning"""

    def __init__(self, opensnitch_interface=None):
        # Feature extractor for state representation
        self.feature_extractor = FeatureExtractor()

        # Calculate state dimension from a sample extraction
        sample_connection = OpenSnitchConnection(
            process_path="/usr/bin/example",
            pid=1000,
            dst_ip="192.168.1.1",
            dst_host="example.com",
            dst_port=443,
            protocol="tcp",
            user_id=1000,
        )
        sample_state = self.feature_extractor.extract(sample_connection)
        state_dim = len(sample_state)

        # Initialize RL agent
        device = "cuda" if torch.cuda.is_available() else "cpu"
        self.agent = DRQNAgent(state_dim=state_dim, device=device)

        # User interface for interaction
        self.ui = AgenTUI()

        # Reward function for reinforcement learning
        self.reward_function = RewardFunction()

        # Rule generator for OpenSnitch rules
        self.rule_generator = RuleGenerator(opensnitch_interface)

        # Training configuration
        self.training_mode = True
        self.auto_apply_rules = True
        self.feedback_probability = 0.1  # Probability of asking for feedback

        # Application state tracking
        self.app_states = {}  # app_id -> last_state mapping

        # Connection history for applications
        self.connection_history = {}  # app_id -> list of connections

        # Load existing model if available
        self.agent.load_model()

        # Training thread
        self.training_thread = None
        self.stop_training = threading.Event()

    def start_training_thread(self):
        """Start background training thread"""
        self.stop_training.clear()
        self.training_thread = threading.Thread(target=self.training_loop)
        self.training_thread.daemon = True
        self.training_thread.start()

    def stop_training_thread(self):
        """Stop background training thread"""
        if self.training_thread and self.training_thread.is_alive():
            self.stop_training.set()
            self.training_thread.join(timeout=2.0)

    def training_loop(self):
        """Background training loop"""
        while not self.stop_training.is_set():
            if self.agent.memory.is_ready_for_training():
                self.agent.update_model()
            time.sleep(5)  # Train every 5 seconds

    def handle_connection(self, connection: OpenSnitchConnection) -> int:
        """
        Handle a new connection request

        Args:
            connection: The connection to handle

        Returns:
            int: Action to take
        """
        # Extract application ID from connection
        app_id = connection.process_path

        # Extract state features
        current_state = self.feature_extractor.extract(connection)

        # Add to app state
        self.app_states[app_id] = current_state

        # Add to connection history
        if app_id not in self.connection_history:
            self.connection_history[app_id] = []
        self.connection_history[app_id].append(connection)

        # Get action from agent (or ask user in exploration mode)
        if (
            self.training_mode and np.random.random() < 0.1
        ):  # Exploration: ask user 10% of the time
            action = self.ui.ask_user(connection)
        else:
            # Get action from agent
            action = self.agent.get_action(app_id, current_state)

            # If action is ASK_USER, get user input
            if action == Actions.ASK_USER:
                action = self.ui.ask_user(connection)

            # Get feedback if needed
            if np.random.random() < self.feedback_probability:
                feedback = self.ui.get_feedback(connection, action)
                # Use feedback to calculate reward
                if feedback is not None:
                    reward = self.reward_function.calculate_reward(
                        current_state, action, user_feedback=feedback
                    )
                    # Add experience to memory
                    self.agent.add_experience(current_state, action, reward, None, True)

        # Calculate reward
        reward = self.reward_function.calculate_reward(current_state, action)

        # Add experience to memory
        self.agent.add_experience(current_state, action, reward, None, True)

        # Generate and apply rule if needed
        if self.auto_apply_rules and action != Actions.ASK_USER:
            rule = self.rule_generator.generate_rule(connection, action)
            # In a real implementation, we would apply the rule to OpenSnitch
            # For this example, we'll just log it
            logger.info(f"Generated rule: {rule}")

        # Update Thompson Sampling model
        state_hash = self.agent.history_tracker.get_state_hash(app_id, current_state)
        self.agent.exploration.update(state_hash, action, reward)

        # If we're allowing a connection to a potentially malicious site, log it
        domain_reputation_idx = 15  # Example index from feature extractor
        if (
            action in [Actions.ALLOW_ONCE, Actions.ALLOW_TEMP, Actions.ALLOW_PERM]
            and current_state[domain_reputation_idx]
            < self.reward_function.reputation_threshold_malicious
        ):
            logger.warning(
                f"Allowing connection to potentially malicious site: {connection.dst_host}"
            )

        # Return the chosen action
        return action

    def save_state(self, path: str = ".weems/data/opensnitch_rl_state.pkl"):
        """Save policy state to disk"""
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(path), exist_ok=True)

        # Save agent model
        self.agent.save_model()

        # Save additional state
        state = {
            "app_states": self.app_states,
            "feature_extractor": {
                "ip_cache": self.feature_extractor.ip_cache,
                "domain_cache": self.feature_extractor.domain_cache,
                "app_cache": self.feature_extractor.app_cache,
                "reputation_data": self.feature_extractor.reputation_data,
            },
            "exploration": {"action_counts": self.agent.exploration.action_counts},
        }

        with open(path, "wb") as f:
            pickle.dump(state, f)

        logger.info(f"Policy state saved to {path}")

    def load_state(self, path: str = ".weems/data/opensnitch_rl_state.pkl"):
        """Load policy state from disk"""
        try:
            with open(path, "rb") as f:
                state = pickle.load(f)

            # Load agent model
            self.agent.load_model()

            # Load additional state
            self.app_states = state["app_states"]
            self.feature_extractor.ip_cache = state["feature_extractor"]["ip_cache"]
            self.feature_extractor.domain_cache = state["feature_extractor"][
                "domain_cache"
            ]
            self.feature_extractor.app_cache = state["feature_extractor"]["app_cache"]
            self.feature_extractor.reputation_data = state["feature_extractor"][
                "reputation_data"
            ]
            self.agent.exploration.action_counts = state["exploration"]["action_counts"]

            logger.info(f"Policy state loaded from {path}")
            return True
        except Exception as e:
            logger.error(f"Error loading policy state: {e}")
            return False


def simulate_connections(policy: OpenSnitchPolicy, n_connections: int = 100):
    """Simulate connection requests to test the policy"""
    # Sample applications
    applications = [
        "/usr/bin/firefox",
        "/usr/bin/chromium",
        "/usr/bin/wget",
        "/usr/bin/curl",
        "/usr/bin/apt",
        "/usr/bin/ssh",
        "/opt/zoom/zoom",
        "/usr/lib/spotify",
        "/usr/bin/python3",
        "/usr/bin/git",
    ]

    # Sample destinations (domains/IPs)
    destinations = [
        ("google.com", "142.250.74.110", 443, "tcp"),
        ("facebook.com", "31.13.72.36", 443, "tcp"),
        ("github.com", "140.82.121.3", 443, "tcp"),
        ("amazon.com", "176.32.103.205", 443, "tcp"),
        ("malware-example.com", "192.168.1.100", 443, "tcp"),
        ("netflix.com", "54.236.124.56", 443, "tcp"),
        ("localhost", "127.0.0.1", 8080, "tcp"),
        ("ads.doubleclick.net", "142.250.74.162", 443, "tcp"),
        ("bank-example.com", "192.168.1.50", 443, "tcp"),
        ("", "8.8.8.8", 53, "udp"),  # DNS request
    ]

    # Generate random connections
    for i in range(n_connections):
        # Choose random application and destination
        app = np.random.choice(applications)
        dest = destinations[np.random.randint(0, len(destinations))]
        domain, ip, port, protocol = dest

        # Create connection
        connection = OpenSnitchConnection(
            process_path=app,
            pid=np.random.randint(1000, 10000),
            dst_ip=ip,
            dst_host=domain,
            dst_port=port,
            protocol=protocol,
            user_id=1000,  # Assume standard user
        )

        # Handle connection
        action = policy.handle_connection(connection)

        # Log the action
        logger.info(
            f"Connection {i+1}/{n_connections}: {app} → {domain or ip}:{port} | Action: {Actions.to_str(action)}"
        )

        # Sleep to simulate time passing
        time.sleep(0.1)

        # Periodically save state
        if (i + 1) % 10 == 0:
            policy.save_state()


class UserInterface:
    """User interface for OpenSnitch policy"""

    def __init__(self):
        self.pending_requests = {}
        self.response_lock = threading.Lock()
        self.response_event = threading.Event()
        self.response = None


class DRQNAgent:
    """Deep Recurrent Q-Network Agent for OpenSnitch policy learning"""

    def __init__(self, state_dim: int, device: str = "cpu"):
        self.device = torch.device(device)

        # Action space
        self.action_dim = Actions.count()

        # Create networks
        self.policy_net = DRQN(state_dim, self.action_dim).to(self.device)
        self.target_net = DRQN(state_dim, self.action_dim).to(self.device)
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()  # Target network is in eval mode

        # Optimizer
        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=0.001)

        # Experience replay
        self.memory = PrioritizedReplayBuffer(capacity=10000)

        # Exploration strategy
        self.exploration = ThompsonSampling()

        # State history tracker
        self.history_tracker = StateHistoryTracker()

        # Training params
        self.batch_size = 32
        self.gamma = 0.99  # Discount factor
        self.tau = 0.01  # Target network update rate
        self.sequence_length = 8  # Length of state sequences for LSTM

        # Logging
        self.writer = SummaryWriter(log_dir=".weems/logs")
        self.train_step = 0

        # Hidden state
        self.hidden_states = {}  # Dict to store hidden states for each application

    def get_action(
        self, app_id: str, state: np.ndarray, eval_mode: bool = False
    ) -> int:
        """
        Get action for a given state

        Args:
            app_id: Application identifier
            state: Current state
            eval_mode: Whether to use evaluation mode (no exploration)

        Returns:
            int: Selected action
        """
        self.policy_net.eval()  # Set policy network to evaluation mode

        # Add state to history
        self.history_tracker.add_state(app_id, state)

        # Get state sequence
        state_seq = self.history_tracker.get_sequence(app_id)

        # Pad or trim sequence to sequence_length
        if len(state_seq) < self.sequence_length:
            # Pad with zeros
            padding = np.zeros(
                (self.sequence_length - len(state_seq), state.shape[0]),
                dtype=np.float32,
            )
            state_seq = np.vstack([padding, state_seq])
        else:
            # Use last sequence_length states
            state_seq = state_seq[-self.sequence_length :]

        # Convert to tensor
        state_tensor = (
            torch.tensor(state_seq, dtype=torch.float32).unsqueeze(0).to(self.device)
        )

        # Get hidden state or initialize if not exists
        if app_id in self.hidden_states:
            hidden = self.hidden_states[app_id]
        else:
            hidden = self.policy_net.init_hidden(batch_size=1)
            hidden = (hidden[0].to(self.device), hidden[1].to(self.device))

        # Get Q-values
        with torch.no_grad():
            q_values, new_hidden = self.policy_net(state_tensor, hidden)

        # Store new hidden state
        self.hidden_states[app_id] = new_hidden

        # Get state hash for exploration
        state_hash = self.history_tracker.get_state_hash(app_id, state)

        # Select action using exploration strategy
        if eval_mode:
            action = q_values.argmax().item()
        else:
            action = self.exploration.select_action(q_values[0], state_hash)

        return action

    def update_model(self):
        """Update model using experiences from replay buffer"""
        if not self.memory.is_ready_for_training(self.batch_size):
            return

        self.policy_net.train()  # Set policy network to training mode

        # Sample batch of experiences
        experiences, indices, weights = self.memory.sample(self.batch_size)

        # Separate experiences
        batch_states = []
        batch_actions = []
        batch_rewards = []
        batch_next_states = []
        batch_dones = []

        for exp in experiences:
            batch_states.append(exp.state)
            batch_actions.append(exp.action)
            batch_rewards.append(exp.reward)
            batch_next_states.append(
                exp.next_state if exp.next_state is not None else exp.state
            )
            batch_dones.append(exp.done)

        # Convert to tensors
        batch_states = torch.tensor(np.array(batch_states), dtype=torch.float32).to(
            self.device
        )
        batch_actions = (
            torch.tensor(batch_actions, dtype=torch.long).unsqueeze(1).to(self.device)
        )
        batch_rewards = (
            torch.tensor(batch_rewards, dtype=torch.float32)
            .unsqueeze(1)
            .to(self.device)
        )
        batch_next_states = torch.tensor(
            np.array(batch_next_states), dtype=torch.float32
        ).to(self.device)
        batch_dones = (
            torch.tensor(batch_dones, dtype=torch.float32).unsqueeze(1).to(self.device)
        )
        weights = weights.to(self.device)

        # Initialize hidden states
        hidden = self.policy_net.init_hidden(self.batch_size)
        hidden = (hidden[0].to(self.device), hidden[1].to(self.device))
        target_hidden = self.target_net.init_hidden(self.batch_size)
        target_hidden = (
            target_hidden[0].to(self.device),
            target_hidden[1].to(self.device),
        )

        # Forward pass for current and next states
        q_values, _ = self.policy_net(batch_states, hidden)
        current_q_values = q_values.gather(1, batch_actions)

        with torch.no_grad():
            next_q_values, _ = self.target_net(batch_next_states, target_hidden)
            next_q_values = next_q_values.max(1, keepdim=True)[0]
            expected_q_values = batch_rewards + self.gamma * next_q_values * (
                1 - batch_dones
            )

        # Calculate TD error
        td_error = (
            torch.abs(current_q_values - expected_q_values).detach().cpu().numpy()
        )

        # Update priorities in replay buffer
        self.memory.update_priorities(indices, td_error)

        # Calculate loss with importance sampling weights
        loss = (
            weights
            * torch.torch.nn.functional.smooth_l1_loss(
                current_q_values, expected_q_values, reduction="none"
            )
        ).mean()

        # Optimize the model
        self.optimizer.zero_grad()
        loss.backward()
        # Gradient clipping to prevent exploding gradients
        torch.nn.utils.clip_grad_norm_(self.policy_net.parameters(), 1.0)
        self.optimizer.step()

        # Soft update target network
        for target_param, policy_param in zip(
            self.target_net.parameters(), self.policy_net.parameters()
        ):
            target_param.data.copy_(
                self.tau * policy_param.data + (1.0 - self.tau) * target_param.data
            )

        # Log training metrics
        self.writer.add_scalar("Loss/train", loss.item(), self.train_step)
        self.train_step += 1

        return loss.item()

    def add_experience(self, state, action, reward, next_state, done):
        """Add experience to replay buffer"""
        self.memory.add(state, action, reward, next_state, done)

    def save_model(self, path: str = ".weems/models/opensnitch_rl_model.pt"):
        """Save model to disk"""
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(path), exist_ok=True)

        # Save model state
        model_state = {
            "policy_net": self.policy_net.state_dict(),
            "target_net": self.target_net.state_dict(),
            "optimizer": self.optimizer.state_dict(),
            "train_step": self.train_step,
        }
        torch.save(model_state, path)
        logger.info(f"Model saved to {path}")

    def load_model(self, path: str = ".weems/models/opensnitch_rl_model.pt"):
        """Load model from disk"""
        try:
            model_state = torch.load(path, map_location=self.device)
            self.policy_net.load_state_dict(model_state["policy_net"])
            self.target_net.load_state_dict(model_state["target_net"])
            self.optimizer.load_state_dict(model_state["optimizer"])
            self.train_step = model_state["train_step"]
            logger.info(f"Model loaded from {path}")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False


def main():
    """Main entry point"""
    print("OpenSnitch Smart Policy with Reinforcement Learning")
    print("=" * 60)

    # Parse command line arguments
    import argparse

    parser = argparse.ArgumentParser(description="OpenSnitch RL Policy")
    parser.add_argument(
        "--simulate", type=int, default=0, help="Run simulation with N connections"
    )
    parser.add_argument(
        "--no-training", action="store_true", help="Disable training mode"
    )
    parser.add_argument(
        "--no-auto-rules",
        action="store_true",
        help="Disable automatic rule application",
    )
    args = parser.parse_args()

    # Create policy
    policy = OpenSnitchPolicy()

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
