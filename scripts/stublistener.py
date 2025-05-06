#!/usr/bin/env python3
"""
OpenSnitch Notification Stream Client

This script connects to an existing OpenSnitch socket and establishes a bidirectional
stream, displaying all incoming messages from the OpenSnitch server.
"""
import pathconf
import grpc
import time
from proto import opensnitch_pb2, opensnitch_pb2_grpc
import os
import json
from datetime import datetime


def log_message(message, prefix=""):
    """Log a message with a timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{timestamp}] {prefix}{message}")


def connect_to_opensnitch():
    """Connect to the OpenSnitch Unix socket"""
    # Unix socket path
    socket_path = "/tmp/osui.sock"

    # Check if socket exists
    if not os.path.exists(socket_path):
        raise FileNotFoundError(f"Socket file not found: {socket_path}")

    log_message(f"Connecting to OpenSnitch socket: unix:{socket_path}")

    # Create a channel using the Unix domain socket
    channel = grpc.insecure_channel(f"unix:{socket_path}")

    # Create a stub (client)
    stub = opensnitch_pb2_grpc.UIStub(channel)

    log_message("Connection established")
    return stub


def notification_reply_iterator():
    """Iterator that produces NotificationReply messages to send to the server"""
    # Send an initial reply to establish the stream
    initial_id = 1
    log_message(f"Sending initial NotificationReply (ID: {initial_id})")

    initial_reply = opensnitch_pb2.NotificationReply(
        id=initial_id, code=opensnitch_pb2.NotificationReplyCode.OK, data=""
    )
    yield initial_reply

    # Keep the stream alive by sending periodic replies
    reply_id = initial_id + 1
    try:
        while True:
            time.sleep(30)  # Send a reply every 30 seconds to keep connection alive
            log_message(f"Sending keepalive NotificationReply (ID: {reply_id})")

            reply = opensnitch_pb2.NotificationReply(
                id=reply_id, code=opensnitch_pb2.NotificationReplyCode.OK, data=""
            )
            yield reply
            reply_id += 1
    except Exception as e:
        log_message(f"Error in notification_reply_iterator: {e}", prefix="ERROR: ")


def format_notification(notification):
    """Format a notification message for display"""
    # Convert action enum to string
    action_name = opensnitch_pb2.Action.Name(notification.type)

    # Format basic notification info
    result = (
        f"Notification ID: {notification.id}\n"
        f"Client Name: {notification.clientName}\n"
        f"Server Name: {notification.serverName}\n"
        f"Action Type: {action_name} ({notification.type})\n"
    )

    # Format data field (try to parse as JSON if possible)
    if notification.data:
        try:
            data_json = json.loads(notification.data)
            result += f"Data: {json.dumps(data_json, indent=2)}\n"
        except json.JSONDecodeError:
            result += f"Data: {notification.data}\n"

    # Add rule information if present
    if notification.rules:
        result += f"Rules Count: {len(notification.rules)}\n"
        for i, rule in enumerate(notification.rules[:3]):  # Show only first 3 rules
            result += (
                f"  Rule {i+1}: {rule.name} ({rule.action}, enabled={rule.enabled})\n"
            )
        if len(notification.rules) > 3:
            result += f"  ... and {len(notification.rules) - 3} more rules\n"

    # Add system firewall info if present
    if notification.HasField("sysFirewall"):
        result += f"System Firewall: Enabled={notification.sysFirewall.Enabled}, Version={notification.sysFirewall.Version}\n"

    return result


def start_notification_stream(stub):
    """Start the notification stream and process incoming messages"""
    log_message("Starting notification stream...")

    try:
        while True:
            # Start the bidirectional streaming RPC
            notification_stream = stub.Notifications(notification_reply_iterator())

            # Process incoming notifications
            log_message("Waiting for notifications...")
            for notification in notification_stream:
                log_message("Received new notification:", prefix="\n")
                formatted = format_notification(notification)
                print(f"{formatted}\n{'-' * 50}")

    except grpc.RpcError as e:
        log_message(f"RPC Error: {e.code()}: {e.details()}", prefix="ERROR: ")
    except Exception as e:
        log_message(f"Unexpected error: {e}", prefix="ERROR: ")


def main():
    try:
        stub = connect_to_opensnitch()
        start_notification_stream(stub)
    except KeyboardInterrupt:
        log_message("Received keyboard interrupt, exiting...")
    except Exception as e:
        log_message(f"Received exception {e}")


if __name__ == "__main__":
    main()
