import random
import os
from collections import defaultdict
from urllib.parse import urlparse
import re

class Request:
    def __init__(self, process_path, process_id, destination_ip, destination_port, protocol, user_id, process_args):
        self.process_path = process_path
        self.process_id = process_id
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.protocol = protocol
        self.user_id = user_id
        self.process_args = process_args


class Classification:
    def __init__(self, request, predictions):
        self.request = request
        self.predictions = predictions


class TrafficFilter:
    def __init__(self, blocklist_dir, epsilon=0.1):
        self.categories = self.load_blocklists(blocklist_dir)  # Load blocklists
        self.belief = {'allowed': 0.51, 'blocked': 0.49}  # Initial belief about allowed/blocked states
        self.epsilon = epsilon  # Exploration rate
        self.reward = 0  # Placeholder for tracking rewards (used for belief update)
    
    def load_blocklists(self, blocklist_dir):
        """
        Loads blocklists from the specified directory and returns a dictionary
        where the key is the category name (file name) and the value is a set of domains/ips.
        """
        blocklists = {}
        for filename in os.listdir(blocklist_dir):
            if filename.endswith('.txt'):  # Assuming the blocklist files are in .txt format
                category = filename.split('.')[0]  # Use the file name (without extension) as the category
                blocklist = set()
                with open(os.path.join(blocklist_dir, filename), 'r') as file:
                    for line in file:
                        line = line.strip()
                        if line and not line.startswith("#"):  # Skip empty lines or comments
                            parts = line.split(' ')
                            if len(parts) > 1:
                                blocklist.add(parts[1])  # Add the domain (remove '0.0.0.0')
                blocklists[category] = blocklist
        return blocklists
    
    def classify_request(self, request: Request):
        """
        Classifies a request based on whether its destination IP or arguments match any domains in the blocklists.
        This updated version ensures precise domain and IP matching.
        """
        predictions = {}
        # Check each category in the blocklists
        for category, domains in self.categories.items():
            matched = False

            # Check for exact domain matches in destination IP or process arguments
            for domain in domains:
                if domain == request.destination_ip or domain in request.process_args:
                    matched = True
                    break  # Exit loop once a match is found

            predictions[category] = matched
        
        return Classification(request, predictions)


    # def is_ip(self, ip: str):
    #     """ A simple check to determine if a string is a valid IP address """
    #     return ip.count('.') == 3 and all(part.isdigit() for part in ip.split('.'))
    
    # def extract_domain(self, text: str):
    #     """
    #     Extracts the domain from a string which might be an IP address, a URL, or a domain.
    #     Handles domain names, IPs, and malformed URLs.
    #     """
    #     # If the text is a URL (with or without a scheme)
    #     parsed_url = urlparse(text)
    #     if parsed_url.netloc:
    #         domain = parsed_url.netloc
    #     else:
    #         domain = text
        
    #     # Normalize IPs like '0-0-0-0-0-0proxy.tserv.se' to '0.0.0.0proxy.tserv.se'
    #     domain = domain.replace('-', '.')
        
    #     # Extract domain from a URL with scheme (e.g., http://example.com or https://example.com)
    #     domain = re.sub(r"^www\.", "", domain)  # Remove "www." prefix
        
    #     return domain
    
    def update_belief(self, action_taken, feedback):
        """ Update belief based on user feedback """
        if action_taken == 'block':
            self.belief['blocked'] += feedback
        else:
            self.belief['allowed'] += feedback

        # Normalize belief values
        total = self.belief['allowed'] + self.belief['blocked']
        print(f"Total belief: {total}")
        if total != 0:
            self.belief['allowed'] /= total
            self.belief['blocked'] /= total
        else:
            print("Total is zero, skipping normalization.")

    def epsilon_greedy(self):
        """ Select action using epsilon-greedy strategy """
        if random.random() < self.epsilon:
            return random.choice(['allow', 'block'])
        else:
            return 'block' if self.belief['blocked'] > self.belief['allowed'] else 'allow'

    def handle_request(self, request: Request):
        """ Handles incoming request by classifying it, selecting an action, and updating belief based on feedback """
        classification = self.classify_request(request)
        print(f"Classified request: {classification.predictions}")
        
        # Decide action using epsilon-greedy
        action_taken = self.epsilon_greedy()
        print(f"Action: {action_taken} for request to {request.destination_ip}")
        
        # Placeholder for user feedback (in real-time, this would be collected from the user interface)
        feedback = self.get_user_feedback(request, action_taken)
        
        # Update belief based on feedback
        self.update_belief(action_taken, feedback)
        
        # Return the action taken
        return action_taken
    
    def get_user_feedback(self, request, action_taken):
        """ Simulate user feedback collection """
        print(f"Was the action '{action_taken}' for request to {request.destination_ip} correct? (good/bad): ", end="")
        feedback = input().strip().lower()
        
        return 1 if feedback == "good" else -1


# Example Blocklist Directory Path
blocklist_dir = r"C:\Users\jonaj\OneDrive - UCB-O365\gitHub\RemoteGithub\weems\lists"  # Directory containing blocklist files like 'phishing.txt', 'ads.txt'

# Example Requests
requests = [
    # Example Requests covering various formats
    Request(process_path="/usr/bin/python3", process_id="67890", destination_ip="affiliatecashpile.go2jump.org", destination_port="80", protocol="tcp", user_id="1000", process_args="wget http://affiliatecashpile.go2jump.org/badfile"),
    Request(process_path="/usr/bin/python3", process_id="67890", destination_ip="088156060096.nidzica.vectranet.pl", destination_port="80", protocol="tcp", user_id="1000", process_args="wget http://088156060096.nidzica.vectranet.pl/badfile"),
    Request(process_path="firefox", process_id="6789", destination_ip="0-0-0-0-0-0proxy.tserv.se", destination_port="443", protocol="TCP", user_id="user4", process_args="https://0-0-0-0-0-0proxy.tserv.se"),
    Request(process_path="chrome", process_id="1234", destination_ip="104.27.135.50", destination_port="443", protocol="TCP", user_id="user1", process_args="http://armdl.adobe.com/"),
    
    Request(process_path="chrome", process_id="2345", destination_ip="185.221.88.122", destination_port="443", protocol="TCP", user_id="user2", process_args="https://www.8cr.purredheanb.online"),
    
    Request(process_path="firefox", process_id="5678", destination_ip="104.26.12.50", destination_port="443", protocol="TCP", user_id="user3", process_args="https://tracking-site.net"),
    
    Request(process_path="firefox", process_id="67890", destination_ip="1-170-195-217.cust.centrio.cz", destination_port="80", protocol="tcp", user_id="1001", process_args="wget http://1-170-195-217.cust.centrio.cz/badfile"),
    
    Request(process_path="firefox", process_id="6789", destination_ip="08.185.87.118.liveadvert.com", destination_port="443", protocol="TCP", user_id="user5", process_args="https://08.185.87.118.liveadvert.com"),
    Request(process_path="firefox", process_id="12345", destination_ip="1-2fly-befragung.de", destination_port="80", protocol="TCP", user_id="user6", process_args="http://1-2fly-befragung.de"),
    Request(process_path="/usr/bin/python3", process_id="67890", destination_ip="0-0-0-6te.net", destination_port="80", protocol="tcp", user_id="1000", process_args="wget http://0-0-0-6te.net/badfile"),
    Request(process_path="/usr/bin/python3", process_id="67890", destination_ip="0-0-0-6te.net", destination_port="80", protocol="tcp", user_id="1000", process_args="wget http://0-0-0-6te.net/badfile"),
    Request(process_path="firefox", process_id="6789", destination_ip="104.27.135.50", destination_port="443", protocol="TCP", user_id="user4", process_args="https://phishing-page.net"),
    Request(process_path="chrome", process_id="1234", destination_ip="142.250.190.78", destination_port="443", protocol="TCP", user_id="user1", process_args="https://www.google.com"),
    Request(process_path="chrome", process_id="2345", destination_ip="185.221.88.122", destination_port="443", protocol="TCP", user_id="user2", process_args="https://phishing-page.net"),
    Request(process_path="firefox", process_id="5678", destination_ip="104.26.12.50", destination_port="443", protocol="TCP", user_id="user3", process_args="https://www.cloudflare.com"),
    Request(process_path="chrome", process_id="6789", destination_ip="104.27.135.50", destination_port="443", protocol="TCP", user_id="user4", process_args="https://tracking-site.net"),
]

# Initialize the traffic filter
filter_system = TrafficFilter(blocklist_dir)

# Simulate processing requests
for request in requests:
    action = filter_system.handle_request(request)
    print(f"Final Action: {action}")
    print(f"Updated Belief: {filter_system.belief}")
    print("-" * 50)
