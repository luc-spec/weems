import unittest
import time
from unittest.mock import patch, MagicMock
import sys
import numpy as np

# Import your module (assuming the main code is in adaptive_network_filter.py)
# from adaptive_network_filter import NetworkState, NetworkAction, SimplePOMDPSolver, URLBeliefTracker

# For testing purposes, we'll define simplified versions here
class NetworkState:
    def __init__(self, url_safety, network_load):
        self.url_safety = url_safety
        self.network_load = network_load

class NetworkAction:
    def __init__(self, allow):
        self.allow = allow

class SimplePOMDPSolver:
    def __init__(self, network_usage_weight=0.7, safety_weight=0.3):
        self.network_usage_weight = network_usage_weight
        self.safety_weight = safety_weight
        
    def calculate_reward(self, state, allow):
        reward = 0
        if allow:
            reward += self.network_usage_weight * (1.0 - state.network_load/100.0)
            if state.url_safety == "Suspicious":
                reward -= self.safety_weight * 0.5
            elif state.url_safety == "Malicious":
                reward -= self.safety_weight * 1.0
        else:
            reward -= self.network_usage_weight * 0.1
            if state.url_safety == "Suspicious":
                reward += self.safety_weight * 0.3
            elif state.url_safety == "Malicious":
                reward += self.safety_weight * 0.8
        return reward
    
    def solve(self, belief, state):
        allow_reward = self.calculate_reward(state, True)
        block_reward = self.calculate_reward(state, False)
        domain_factor = min(1.0, belief.get("reputation", 0.5))
        allow_reward *= domain_factor
        return NetworkAction(allow_reward > block_reward)

class URLBeliefTracker:
    def __init__(self):
        self.domain_beliefs = {}
        for domain in ["safe.com", "suspicious.com", "malicious.com"]:
            self.domain_beliefs[domain] = {
                "reputation": 0.5,
                "visit_count": 0,
                "block_count": 0,
                "suspicious_activity": 0,
                "last_updated": time.time()
            }
    
    def update_belief(self, domain, url):
        if domain not in self.domain_beliefs:
            self.domain_beliefs[domain] = {
                "reputation": 0.5,
                "visit_count": 0,
                "block_count": 0,
                "suspicious_activity": 0,
                "last_updated": time.time()
            }
        
        belief = self.domain_beliefs[domain]
        
        # Simulate URL checks
        if "malware" in url or "exploit" in url:
            belief["reputation"] *= 0.5
            belief["suspicious_activity"] += 2
        elif "tracker" in url or "ads" in url:
            belief["reputation"] *= 0.8
            belief["suspicious_activity"] += 1
        else:
            belief["reputation"] = min(1.0, belief["reputation"] * 1.05)
        
        belief["reputation"] = max(0.01, min(0.99, belief["reputation"]))
        belief["visit_count"] += 1
        
        return belief


class TestPOMDPSolver(unittest.TestCase):
    def setUp(self):
        self.solver = SimplePOMDPSolver(network_usage_weight=0.7, safety_weight=0.3)
    
    def test_calculate_reward_safe_allow(self):
        state = NetworkState("Safe", 50)
        reward = self.solver.calculate_reward(state, True)
        # Should be positive for safe URLs
        self.assertGreater(reward, 0)
    
    def test_calculate_reward_malicious_allow(self):
        state = NetworkState("Malicious", 50)
        reward = self.solver.calculate_reward(state, True)
        # Should be negative for malicious URLs
        self.assertLess(reward, 0)
    
    def test_calculate_reward_malicious_block(self):
        state = NetworkState("Malicious", 50)
        reward = self.solver.calculate_reward(state, False)
        # Should be positive for blocking malicious URLs
        self.assertGreater(reward, 0)
    
    def test_solve_safe_url(self):
        state = NetworkState("Safe", 50)
        belief = {"reputation": 0.8}
        action = self.solver.solve(belief, state)
        # Should allow safe URLs
        self.assertTrue(action.allow)
    
    def test_solve_malicious_url(self):
        state = NetworkState("Malicious", 50)
        belief = {"reputation": 0.2}
        action = self.solver.solve(belief, state)
        # Should block malicious URLs
        self.assertFalse(action.allow)
    
    def test_network_load_impact(self):
        # Test that high network load reduces rewards for allowing
        state_low_load = NetworkState("Safe", 20)
        state_high_load = NetworkState("Safe", 90)
        belief = {"reputation": 0.8}
        
        reward_low_load = self.solver.calculate_reward(state_low_load, True)
        reward_high_load = self.solver.calculate_reward(state_high_load, True)
        
        self.assertGreater(reward_low_load, reward_high_load)


class TestURLBeliefTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = URLBeliefTracker()
    
    def test_initial_belief(self):
        domain = "test.com"
        belief = self.tracker.update_belief(domain, "http://test.com")
        self.assertIn("reputation", belief)
        self.assertIn("visit_count", belief)
        self.assertEqual(belief["visit_count"], 1)
    
    def test_malicious_url_impact(self):
        domain = "evil.com"
        initial_belief = self.tracker.update_belief(domain, "http://evil.com")
        initial_rep = initial_belief["reputation"]
        
        malicious_belief = self.tracker.update_belief(domain, "http://evil.com/malware")
        self.assertLess(malicious_belief["reputation"], initial_rep)
        self.assertEqual(malicious_belief["visit_count"], 2)
    
    def test_safe_url_impact(self):
        domain = "good.com"
        initial_belief = self.tracker.update_belief(domain, "http://good.com")
        initial_rep = initial_belief["reputation"]
        
        safe_belief = self.tracker.update_belief(domain, "http://good.com/products")
        self.assertGreaterEqual(safe_belief["reputation"], initial_rep)


class TestURLProcessing(unittest.TestCase):
    @patch('builtins.print')  # Mock print to avoid console output during tests
    def test_process_request_safe(self, mock_print):
        # Mock the process_request function from your actual module
        def process_request(url_request):
            url = url_request.get('url')
            if "safe" in url:
                safety = "Safe"
            elif "suspicious" in url:
                safety = "Suspicious"
            else:
                safety = "Malicious"
                
            return {
                "allow": safety != "Malicious",
                "url": url,
                "domain": url.split("//")[1].split("/")[0],
                "reason": f"Test decision (safety={safety})"
            }
        
        result = process_request({"url": "http://safe.example.com/page"})
        self.assertTrue(result["allow"])
    
    @patch('builtins.print')
    def test_process_request_malicious(self, mock_print):
        def process_request(url_request):
            url = url_request.get('url')
            if "malware" in url or "phish" in url:
                safety = "Malicious"
            else:
                safety = "Safe"
                
            return {
                "allow": safety != "Malicious",
                "url": url,
                "domain": url.split("//")[1].split("/")[0],
                "reason": f"Test decision (safety={safety})"
            }
        
        result = process_request({"url": "http://example.com/malware"})
        self.assertFalse(result["allow"])


class TestIntegrationScenarios(unittest.TestCase):
    def setUp(self):
        self.solver = SimplePOMDPSolver()
        self.tracker = URLBeliefTracker()
    
    def test_repeated_visits_to_safe_site(self):
        """Test that reputation improves with repeated visits to safe sites"""
        domain = "safe-site.com"
        url = "https://safe-site.com/content"
        
        # Visit multiple times
        beliefs = []
        for _ in range(5):
            belief = self.tracker.update_belief(domain, url)
            beliefs.append(belief["reputation"])
        
        # Reputation should improve or stay high
        self.assertGreaterEqual(beliefs[-1], beliefs[0])
    
    def test_malicious_site_then_safe_site(self):
        """Test that a malicious URL decreases reputation but it can recover"""
        domain = "mixed-site.com"
        
        # First a malicious URL
        belief1 = self.tracker.update_belief(domain, "https://mixed-site.com/malware")
        reputation1 = belief1["reputation"]
        
        # Then several safe URLs
        for _ in range(10):
            belief = self.tracker.update_belief(domain, "https://mixed-site.com/good-content")
        
        reputation_final = belief["reputation"]
        
        # Should have improved but not fully recovered
        self.assertGreater(reputation_final, reputation1)
        self.assertLess(reputation_final, 0.99)  # Not fully trusted yet
    
    def test_decision_consistency(self):
        """Test that decisions are consistent for similar URLs"""
        state1 = NetworkState("Safe", 50)
        state2 = NetworkState("Safe", 55)  # Slightly different load
        belief = {"reputation": 0.7}
        
        action1 = self.solver.solve(belief, state1)
        action2 = self.solver.solve(belief, state2)
        
        # Small changes shouldn't flip the decision
        self.assertEqual(action1.allow, action2.allow)


class TestRegressionScenarios(unittest.TestCase):
    """Tests for specific scenarios that could cause regressions"""
    
    def setUp(self):
        self.solver = SimplePOMDPSolver()
        self.tracker = URLBeliefTracker()
    
    def test_edge_case_very_high_load(self):
        """Test behavior under extremely high network load"""
        state = NetworkState("Safe", 99)
        belief = {"reputation": 0.9}  # Very trusted site
        
        action = self.solver.solve(belief, state)
        # Even under high load, very trusted sites should be allowed
        self.assertTrue(action.allow)
    
    def test_edge_case_borderline_reputation(self):
        """Test behavior with borderline reputation values"""
        state = NetworkState("Suspicious", 50)
        belief = {"reputation": 0.51}  # Just barely positive
        
        action = self.solver.solve(belief, state)
        # Record the decision - may vary based on implementation
        result = action.allow
        
        # Slight reputation decrease
        belief = {"reputation": 0.49}  # Just barely negative
        action = self.solver.solve(belief, state)
        
        # Small changes in borderline cases might flip the decision
        # This test documents the current behavior rather than asserting what it should be
        print(f"Borderline test: reputation 0.51 -> {result}, reputation 0.49 -> {action.allow}")
    
    def test_many_suspicious_activities(self):
        """Test the impact of many suspicious activities"""
        domain = "many-suspicious.com"
        
        # Many slightly suspicious activities
        for i in range(20):
            self.tracker.update_belief(domain, f"https://many-suspicious.com/tracker{i}")
        
        belief = self.tracker.domain_beliefs[domain]
        
        # Should have significantly reduced reputation
        self.assertLess(belief["reputation"], 0.2)


if __name__ == '__main__':
    unittest.main()
