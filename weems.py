'''

Weems

  An adaptive network filter service.

'''

# --- Full imports ---
import dbus
import time
import numpy as np
import threading
import re
import urllib.parse

# --- Partial imports ---
from dataclasses import dataclass
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from gi.repository import GLib
from dbus.mainloop.glib import DBusGMainLoop

# URL pattern database (simplified example)
malicious_patterns = [r'malware', r'phish', r'exploit']
suspicious_patterns = [r'tracker', r'ads\.', r'analytics']

# Global objects
request_queue = Queue()
result_queue = Queue()
belief_tracker = URLBeliefTracker()
pomdp_solver = SimplePOMDPSolver()


@dataclass
class State:
    '''Data structure for keeping track of allow/block states'''
    allowed: tuple[str]
    blocked: tuple[str]


@dataclass
class StateSpace:
    '''
    StateSpace: FIFO list of allow and block list tuples 
    '''
    _history: list[State]

    def __init__(self, history_length: int = 10000):
        self._max_len = history_length

    def current(self):
        '''
        Get the most recent allow/block lists
        '''
        return self._history[0]

    def history(self):
        '''
        Get the full history of state space
        '''
        return self._history

    def add(self, s: State):
        '''
        Add a State to the 0 index of our history
        '''
        self._history.insert(State)

    def remove(self):
        '''
        With no arguments, just remove our last entry
        '''
        self._history.pop(0)

    def remove(self, url: str):
        '''
        If we have a url argument, then make a new history entry
        with that url removed
        '''
        for entry in self._history:
            if url in entry.blocked:
                self._history.remove(entry)

# ---- POMDP Classes ----


class NetworkState:
    def __init__(self, url_safety, network_load):
        self.url_safety = url_safety  # Safe, Suspicious, Malicious
        self.network_load = network_load  # Current network load percentage


class NetworkAction:
    def __init__(self, allow):
        self.allow = allow  # True = allow, False = block


class NetworkObservation:
    def __init__(self, observed_behavior):
        self.observed_behavior = observed_behavior  # Normal, Suspicious

# Simplified POMDP solver (in practice, use a library like pomdp_py)


class SimplePOMDPSolver:
    def __init__(self, network_usage_weight=0.7, safety_weight=0.3):
        self.network_usage_weight = network_usage_weight
        self.safety_weight = safety_weight

    def calculate_reward(self, state, allow):
        reward = 0

        # Reward for network utilization
        if allow:
            reward += self.network_usage_weight * \
                (1.0 - state.network_load/100.0)

            # Penalty for allowing unsafe URLs
            if state.url_safety == "Suspicious":
                reward -= self.safety_weight * 0.5
            elif state.url_safety == "Malicious":
                reward -= self.safety_weight * 1.0
        else:
            # Small penalty for blocking to encourage network usage
            reward -= self.network_usage_weight * 0.1

            # Reward for blocking unsafe URLs
            if state.url_safety == "Suspicious":
                reward += self.safety_weight * 0.3
            elif state.url_safety == "Malicious":
                reward += self.safety_weight * 0.8

        return reward

    def solve(self, belief, state):
        # Calculate expected rewards for each action
        allow_reward = self.calculate_reward(state, True)
        block_reward = self.calculate_reward(state, False)

        # Factor in domain reputation from belief
        domain_factor = min(1.0, belief.get("reputation", 0.5))
        allow_reward *= domain_factor

        # Choose action with highest reward
        return NetworkAction(allow_reward > block_reward)

# ---- URL Processing ----

class URLBeliefTracker:
    def __init__(self):
        self.domain_beliefs = defaultdict(lambda: {
            "reputation": 0.5,  # 0.0 bad - 1.0 good
            "visit_count": 0,
            "block_count": 0,
            "suspicious_activity": 0,
            "last_updated": time.time()
        })

    def update_belief(self, domain, url):
        """Update belief based on domain history and URL patterns"""
        belief = self.domain_beliefs[domain]

        # Decay older information (time-based forgetting)
        time_diff = time.time() - belief["last_updated"]
        if time_diff > 3600:  # 1 hour
            # Max 1 day for full decay
            decay_factor = min(1.0, time_diff / 86400)
            belief["reputation"] = 0.5 + \
                (belief["reputation"] - 0.5) * (1 - decay_factor)
            belief["last_updated"] = time.time()

        # Check for suspicious patterns
        is_suspicious = any(re.search(pattern, url)
                            for pattern in suspicious_patterns)
        is_malicious = any(re.search(pattern, url)
                           for pattern in malicious_patterns)

        # Update belief based on URL checks
        if is_malicious:
            belief["reputation"] *= 0.5  # Strong negative impact
            belief["suspicious_activity"] += 2
        elif is_suspicious:
            belief["reputation"] *= 0.8  # Moderate negative impact
            belief["suspicious_activity"] += 1
        else:
            # Good URL - slightly improve reputation
            belief["reputation"] = min(1.0, belief["reputation"] * 1.05)

        # Normalize reputation
        belief["reputation"] = max(0.01, min(0.99, belief["reputation"]))
        belief["visit_count"] += 1

        return belief


def get_current_network_load():
    """Get current network load percentage (0-100)"""
    # In a real implementation, measure actual network throughput
    # For simplicity, we'll return a random value here
    return np.random.randint(10, 80)


def extract_url_from_connection(connection_data):
    """Extract URL from OpenSnitch connection data"""
    try:
        # In a real implementation, parse OpenSnitch data properly
        # This is a placeholder example
        protocol = connection_data.get("protocol", "")
        dst_host = connection_data.get("dst_host", "")
        dst_port = connection_data.get("dst_port", 80)

        if protocol.lower() in ["tcp", "udp"] and dst_host:
            scheme = "https" if dst_port == 443 else "http"
            return f"{scheme}://{dst_host}:{dst_port}"
        return None
    except Exception as e:
        print(f"Error extracting URL: {e}")
        return None


def process_request(url_request):
    """Process a URL request and make decision"""
    url = url_request.get('url')
    domain = urllib.parse.urlparse(url).netloc

    # Extract features for POMDP
    is_suspicious = any(re.search(pattern, url)
                        for pattern in suspicious_patterns)
    is_malicious = any(re.search(pattern, url)
                       for pattern in malicious_patterns)

    if is_malicious:
        safety = "Malicious"
    elif is_suspicious:
        safety = "Suspicious"
    else:
        safety = "Safe"

    # Get current network load
    network_load = get_current_network_load()

    # Create POMDP state
    current_state = NetworkState(safety, network_load)

    # Update belief and make decision using POMDP
    belief = belief_tracker.update_belief(domain, url)
    action = pomdp_solver.solve(belief, current_state)

    print(
        f"URL: {url} | Safety: {safety} | Decision: {'ALLOW' if action.allow else 'BLOCK'}")

    # Return decision to OpenSnitch
    return {
        "allow": action.allow,
        "url": url,
        "domain": domain,
        "reason": f"POMDP decision (safety={safety}, load={network_load}%)"
    }


def worker(worker_id):
    """Worker thread for processing URL requests"""
    print(f"Worker {worker_id} started")
    while True:
        url_request = request_queue.get()
        if url_request is None:  # Poison pill for shutdown
            break

        # Process the URL request
        decision = process_request(url_request)
        result_queue.put(decision)
        request_queue.task_done()


def result_handler():
    """Thread for handling processing results"""
    while True:
        result = result_queue.get()
        if result is None:  # Poison pill
            break

        # In a real implementation, send decision back to OpenSnitch
        # For now, just log the result
        print(
            f"Decision for {result['url']}: {'ALLOW' if result['allow'] else 'BLOCK'} - {result['reason']}")
        result_queue.task_done()


def handle_connection(connection_data):
    """Handle new connection event from OpenSnitch"""
    url = extract_url_from_connection(connection_data)
    if url:
        print(f"New connection: {url}")
        request_queue.put({"url": url, "connection_data": connection_data})


def setup_opensnitch_listener():
    """Set up OpenSnitch D-Bus listener"""
    try:
        # Connect to OpenSnitch D-Bus interface
        bus = dbus.SystemBus()

        opensnitch_object = bus.get_object(
            "io.github.evilsocket.opensnitch",
            "/io/github/evilsocket/opensnitch/rule"
        )

        opensnitch_interface = dbus.Interface(
            opensnitch_object,
            "io.github.evilsocket.opensnitch.Rule"
        )

        # Register for connection events
        opensnitch_interface.connect_to_signal(
            "NewConnection", handle_connection)

        print("OpenSnitch listener configured successfully")

        # Start the main loop
        loop = GLib.MainLoop()
        loop.run()

    except Exception as e:
        print(f"Error setting up OpenSnitch listener: {e}")


def main():
    """Main function to start the application"""
    print("Starting Adaptive Network Filter")

    # Start worker threads
    NUM_WORKERS = 8  # Adjust based on your system
    workers = []
    with ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
        # Submit worker tasks
        for i in range(NUM_WORKERS):
            workers.append(executor.submit(worker, i))

        # Start result handler
        result_thread = threading.Thread(target=result_handler)
        result_thread.daemon = True
        result_thread.start()

        # Set up OpenSnitch listener in the main thread
        try:
            # Initialize D-Bus connection
            DBusGMainLoop(set_as_default=True)
            setup_opensnitch_listener()
        except KeyboardInterrupt:
            print("Shutting down...")
        finally:
            # Send poison pills to workers and result handler
            for _ in range(NUM_WORKERS):
                request_queue.put(None)
            result_queue.put(None)


if __name__ == "__main__":
    main()
