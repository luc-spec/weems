from numpy.random import choice, randint
from time import time

from DecisionStructure import Actions

# OpenSnitch API - mock import for demonstration
# In a real implementation, this would import from OpenSnitch's Python API
class OpenSnitchConnection:
    def __init__(self, process_path="", pid=0, dst_ip="", dst_host="", 
                 dst_port=0, protocol="", user_id=0):
        self.process_path = process_path
        self.pid = pid
        self.dst_ip = dst_ip
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.protocol = protocol
        self.user_id = user_id
        self.timestamp = time()

#class RuleGenerator:
#    def __init__(self, opensnitch_daemon):
#        self.daemon = opensnitch_daemon
#
#    def action_to_rule(self, action, state):
#        # Extract connection details
#        proc_path = state["process_path"]
#        dest_host = state["destination_host"]
#        dest_port = state["destination_port"]
#        protocol = state["protocol"]
#
#        # Determine rule duration based on action
#        if action == Actions.ALLOW_ONCE:
#            duration = "once"
#        elif action == Actions.ALLOW_TEMP:
#            duration = "until_quit"
#        elif action == Actions.ALLOW_PERM:
#            duration = "always"
#        else:
#            # Block actions
#            duration = "once" if action == Actions.BLOCK_ONCE else "always"
#
#        # Create OpenSnitch rule
#        rule = {
#            "name": f"RL_generated_{uuid.uuid4().hex[:8]}",
#            "enabled": True,
#            "precedence": 50,  # Middle priority
#            "action": (
#                "allow"
#                if action
#                in [Actions.ALLOW_ONCE, Actions.ALLOW_TEMP, Actions.ALLOW_PERM]
#                else "deny"
#            ),
#            "duration": duration,
#            "operator": {
#                "type": "simple",
#                "operand": "process.path",
#                "data": proc_path,
#            },
#            "conditions": [
#                {"type": "simple", "operand": "dest.host", "data": dest_host},
#                {"type": "simple", "operand": "dest.port", "data": dest_port},
#                {"type": "simple", "operand": "protocol", "data": protocol},
#            ],
#        }
#
#        return rule
