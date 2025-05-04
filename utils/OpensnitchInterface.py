from numpy.random import choice, randint
from time import time
from typing import Dict
from uuid import uuid4

from .DecisionStructure import Actions


# OpenSnitch API - mock import for demonstration
# In a real implementation, this would import from OpenSnitch's Python API
class OpenSnitchConnection:
    def __init__(
        self,
        process_path="",
        pid=0,
        dst_ip="",
        dst_host="",
        dst_port=0,
        protocol="",
        user_id=0,
    ):
        self.process_path = process_path
        self.pid = pid
        self.dst_ip = dst_ip
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.protocol = protocol
        self.user_id = user_id
        self.timestamp = time()


class RuleGenerator:
    """Generate OpenSnitch rules from RL model decisions"""

    def __init__(self, opensnitch_interface=None):
        self.opensnitch = opensnitch_interface

    def generate_rule(self, connection: OpenSnitchConnection, action: int) -> Dict:
        """Generate an OpenSnitch rule based on the connection and action"""
        # Extract relevant fields
        proc_path = connection.process_path
        dest_host = connection.dst_host
        dest_ip = connection.dst_ip
        dest_port = connection.dst_port
        protocol = connection.protocol

        # Determine rule duration based on action
        if action == Actions.ALLOW_ONCE or action == Actions.BLOCK_ONCE:
            duration = "once"
        elif action == Actions.ALLOW_TEMP or action == Actions.BLOCK_TEMP:
            duration = "until_quit"
        else:  # Permanent rules
            duration = "always"

        # Determine allow/deny
        is_allow = action in [
            Actions.ALLOW_ONCE,
            Actions.ALLOW_TEMP,
            Actions.ALLOW_PERM,
        ]

        # Create rule
        rule = {
            "name": f"RL_generated_{uuid4().hex[:8]}",
            "enabled": True,
            "precedence": 50,  # Middle priority
            "action": "allow" if is_allow else "deny",
            "duration": duration,
            "operator": {
                "type": "simple",
                "operand": "process.path",
                "data": proc_path,
            },
            "conditions": [
                {
                    "type": "simple",
                    "operand": "dest.host" if dest_host else "dest.ip",
                    "data": dest_host if dest_host else dest_ip,
                },
                {"type": "simple", "operand": "dest.port", "data": str(dest_port)},
                {"type": "simple", "operand": "protocol", "data": protocol},
            ],
        }

        return rule
