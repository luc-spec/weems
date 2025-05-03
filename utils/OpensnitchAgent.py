import grpc
import time
import sys
import logging
from concurrent import futures

## Local Imports
from . import pathconf

# These imports will work after you've run `make generate-proto`
from proto import opensnitch_pb2
from proto import opensnitch_pb2_grpc

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("OpenSnitchAgent")


class OpenSnitchAgent:
    def __init__(self, server_address="unix:///tmp/osui.sock"):
        """Initialize connection to OpenSnitch daemon.

        Args:
            server_address: The address of the OpenSnitch daemon's gRPC server.
                Default is the standard Unix socket path.
        """
        logger.info(f"Connecting to OpenSnitch daemon at {server_address}")
        self.channel = grpc.insecure_channel(server_address)
        self.stub = opensnitch_pb2_grpc.UIStub(self.channel)
        self.agent_id = "my-opensnitch-agent-1.0"

    def start_notifications(self):
        """Start receiving notifications about connection events."""
        try:
            # Create a notification request
            notification_request = opensnitch_pb2.Notification(
                id=self.agent_id, type=opensnitch_pb2.Action
            )

            logger.info(f"Starting notification stream with ID: {self.agent_id}")

            # Stream notifications from the server
            notifications = self.stub.Notifications(notification_request)

            for notification in notifications:
                # Process each connection notification
                self.process_notification(notification)

        except grpc.RpcError as e:
            logger.error(f"RPC Error: {e}")
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                logger.error(
                    "OpenSnitch daemon appears to be unavailable. Is it running?"
                )
            return False
        except KeyboardInterrupt:
            logger.info("Agent shutting down gracefully")
            return True
        except Exception as e:
            logger.exception(f"Unexpected error: {e}")
            return False

    def process_notification(self, notification):
        """Process a notification and make a decision.

        Args:
            notification: A opensnitch_pb2.Notification object containing connection details
        """
        if notification.type != opensnitch_pb2.NOTIFICATION_TYPE_CONNECTION:
            logger.warning(
                f"Received unexpected notification type: {notification.type}"
            )
            return

        conn = notification.connection

        # Log connection details
        logger.info(
            f"New connection: {conn.process_path} ({conn.process_id}) -> {conn.dst_ip}:{conn.dst_port}"
        )
        logger.debug(
            f"Connection details: protocol={conn.protocol}, user_id={conn.user_id}"
        )

        # Implement your decision logic here
        # This is a simple example based on port number
        allow = self._make_decision(conn)

        # Send the decision back to OpenSnitch
        self.send_decision(conn, allow)

    def _make_decision(self, conn):
        """Custom logic to decide whether to allow or block a connection.

        Override this method to implement your own decision logic.

        Args:
            conn: Connection details

        Returns:
            bool: True to allow, False to block
        """
        # Example logic: Allow HTTP/HTTPS and block everything else
        if conn.dst_port in [80, 443]:
            logger.info(f"Allowing connection to port {conn.dst_port}")
            return True
        # Example: Block specific IPs
        elif conn.dst_ip == "192.168.1.100":
            logger.info(f"Blocking connection to blacklisted IP: {conn.dst_ip}")
            return False
        # Example: Allow specific applications
        elif "firefox" in conn.process_path.lower():
            logger.info(f"Allowing Firefox connection")
            return True
        # Default action
        else:
            logger.info(f"Blocking connection to port {conn.dst_port} by default")
            return False

    def send_decision(self, connection, allow):
        """Send a decision (allow/block) back to OpenSnitch.

        Args:
            connection: The connection object from the notification
            allow: Boolean indicating whether to allow the connection
        """
        # Create a unique name for this rule
        rule_name = f"{self.agent_id}-{connection.process_id}-{connection.dst_ip}-{connection.dst_port}"

        # Create the rule reply
        decision = opensnitch_pb2.RuleReply(
            name=rule_name,
            enabled=True,
            action=opensnitch_pb2.ACCEPT if allow else opensnitch_pb2.DROP,
            duration=opensnitch_pb2.ONCE,  # Options: ONCE, RESTART, ALWAYS
            operator=opensnitch_pb2.SIMPLE,
            # Define rule conditions - customize these based on your needs
            condition=[
                opensnitch_pb2.Rule(
                    field=opensnitch_pb2.PROCESS_PATH, value=connection.process_path
                ),
                opensnitch_pb2.Rule(
                    field=opensnitch_pb2.DEST_HOST, value=connection.dst_ip
                ),
                opensnitch_pb2.Rule(
                    field=opensnitch_pb2.DEST_PORT, value=str(connection.dst_port)
                ),
            ],
        )

        try:
            # Send the rule to OpenSnitch
            response = self.stub.RuleResponse(decision)
            logger.info(
                f"Decision sent: {'ALLOW' if allow else 'BLOCK'} - Rule: {rule_name}"
            )
        except grpc.RpcError as e:
            logger.error(f"Error sending decision: {e}")

def main():
    """Main entry point"""
    print("OpenSnitchAgent -- Check Opensnitch Integration")
    print("=" * 60)

    # Parse command line arguments
    import argparse

    osa = OpenSnitchAgent()

    try:
        # Run simulation
        print(f"Listening for Opensnitch gRPC information..")
        osa.start_notifications()

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nShutting down...")

    print("Done.")


if __name__ == "__main__":
    main()
