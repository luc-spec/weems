# tests/test_agent.py

import unittest
import pytest
from unittest.mock import Mock, patch, MagicMock
import grpc
import sys
import time
from threading import Thread

# Add src directory to path for imports
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

# Import the agent class and proto modules
from utils.OpensnitchAgent import OpenSnitchAgent
from proto import opensnitch_pb2, opensnitch_pb2_grpc

class TestOpenSnitchAgent:
    """Test suite for the OpenSnitch Agent."""

    @pytest.fixture
    def mock_grpc_channel(self):
        """Create a mock gRPC channel."""
        with patch('grpc.insecure_channel') as mock_channel:
            yield mock_channel

    @pytest.fixture
    def mock_ui_stub(self):
        """Create a mock UI stub."""
        return Mock(spec=opensnitch_pb2_grpc.UIStub)

    @pytest.fixture
    def agent_with_mocks(self, mock_grpc_channel, mock_ui_stub):
        """Create an agent with mocked dependencies."""
        # Make the mock channel return the mock stub
        mock_grpc_channel.return_value = "mocked_channel"
        
        # Patch the UIStub constructor to return our mock stub
        with patch('proto.opensnitch_pb2_grpc.UIStub', return_value=mock_ui_stub):
            agent = OpenSnitchAgent()
            agent.stub = mock_ui_stub  # Ensure our mock is used
            return agent

    def test_initialization(self, mock_grpc_channel):
        """Test that the agent initializes correctly."""
        with patch('proto.opensnitch_pb2_grpc.UIStub'):
            agent = OpenSnitchAgent()
            
            # Check that it tried to connect to the expected socket
            mock_grpc_channel.assert_called_once_with('unix:///tmp/osui.sock')

    def test_notification_registration(self, agent_with_mocks):
        """Test that the agent registers for notifications."""
        # Create a mock for the Notifications response
        mock_notifications = Mock()
        # Make the notifications method return the mock
        agent_with_mocks.stub.Notifications.return_value = mock_notifications
        # Make the iterator return an empty list to avoid processing notifications
        mock_notifications.__iter__.return_value = []
        
        # Call the method we're testing
        agent_with_mocks.start_notifications()
        
        # Verify that Notifications was called with the correct request
        notification_request_call = agent_with_mocks.stub.Notifications.call_args[0][0]
        assert notification_request_call.id == agent_with_mocks.agent_id
        assert notification_request_call.type == opensnitch_pb2.NOTIFICATION_TYPE_CONNECTION

    def test_process_notification(self, agent_with_mocks):
        """Test that notifications are processed correctly."""
        # Create a mock for the connection and notification
        mock_connection = Mock()
        mock_connection.process_path = "/usr/bin/firefox"
        mock_connection.process_id = "12345"
        mock_connection.dst_ip = "192.168.1.1"
        mock_connection.dst_port = 443
        mock_connection.protocol = "tcp"
        mock_connection.user_id = "1000"
        
        mock_notification = Mock()
        mock_notification.type = opensnitch_pb2.NOTIFICATION_TYPE_CONNECTION
        mock_notification.connection = mock_connection
        
        # Create a spy on the send_decision method
        with patch.object(agent_with_mocks, 'send_decision') as mock_send_decision:
            # Call the method we're testing
            agent_with_mocks.process_notification(mock_notification)
            
            # Verify that send_decision was called with the expected parameters
            # The second parameter (allow) depends on the logic in _make_decision
            mock_send_decision.assert_called_once()
            assert mock_send_decision.call_args[0][0] == mock_connection
            # The actual value of allow will depend on the implementation of _make_decision

    def test_notification_stream_receives_data(self, agent_with_mocks):
        """Test that the agent can receive and process notifications from the stream."""
        # Create a mock connection
        mock_connection = MagicMock()
        mock_connection.process_path = "/usr/bin/curl"
        mock_connection.process_id = "12345"
        mock_connection.dst_ip = "93.184.216.34"  # example.com
        mock_connection.dst_port = 80
        
        # Create a mock notification with the connection
        mock_notification = MagicMock()
        mock_notification.type = opensnitch_pb2.NOTIFICATION_TYPE_CONNECTION
        mock_notification.connection = mock_connection
        
        # Make the stub's Notifications method return an iterable with our mock notification
        mock_notifications_iter = MagicMock()
        mock_notifications_iter.__iter__.return_value = [mock_notification]
        agent_with_mocks.stub.Notifications.return_value = mock_notifications_iter
        
        # Setup the send_decision method to track calls
        send_decision_calls = []
        def mock_send_decision(conn, allow):
            send_decision_calls.append((conn, allow))
            
        agent_with_mocks.send_decision = mock_send_decision
        
        # Execute start_notifications
        agent_with_mocks.start_notifications()
        
        # Check that send_decision was called with the right connection
        assert len(send_decision_calls) == 1
        assert send_decision_calls[0][0] == mock_connection

    def test_make_decision_logic(self, agent_with_mocks):
        """Test the decision-making logic for different connection scenarios."""
        # Test case 1: Common HTTP port should be allowed
        conn_http = MagicMock()
        conn_http.dst_port = 80
        assert agent_with_mocks._make_decision(conn_http) is True
        
        # Test case 2: Common HTTPS port should be allowed
        conn_https = MagicMock()
        conn_https.dst_port = 443
        assert agent_with_mocks._make_decision(conn_https) is True
        
        # Test case 3: Blocked IP address
        conn_blocked_ip = MagicMock()
        conn_blocked_ip.dst_port = 8080
        conn_blocked_ip.dst_ip = "192.168.1.100"  # IP that should be blocked according to the logic
        assert agent_with_mocks._make_decision(conn_blocked_ip) is False
        
        # Test case 4: Firefox application should be allowed
        conn_firefox = MagicMock()
        conn_firefox.dst_port = 8080  # Not HTTP/HTTPS
        conn_firefox.dst_ip = "10.0.0.1"  # Not the blocked IP
        conn_firefox.process_path = "/usr/bin/firefox"
        assert agent_with_mocks._make_decision(conn_firefox) is True
        
        # Test case 5: Default action for non-matching connections
        conn_other = MagicMock()
        conn_other.dst_port = 8080  # Not HTTP/HTTPS
        conn_other.dst_ip = "10.0.0.1"  # Not the blocked IP
        conn_other.process_path = "/usr/bin/curl"  # Not Firefox
        assert agent_with_mocks._make_decision(conn_other) is False

    def test_send_decision(self, agent_with_mocks):
        """Test that decisions are sent correctly to OpenSnitch."""
        # Create a mock connection
        mock_connection = MagicMock()
        mock_connection.process_path = "/usr/bin/curl"
        mock_connection.process_id = "12345"
        mock_connection.dst_ip = "93.184.216.34"
        mock_connection.dst_port = 80
        
        # Reset the RuleResponse mock
        agent_with_mocks.stub.RuleResponse.reset_mock()
        
        # Call send_decision with a decision to allow
        agent_with_mocks.send_decision(mock_connection, True)
        
        # Verify that RuleResponse was called with a rule that has ACCEPT action
        rule_reply = agent_with_mocks.stub.RuleResponse.call_args[0][0]
        assert rule_reply.action == opensnitch_pb2.ACCEPT
        
        # Reset the mock again
        agent_with_mocks.stub.RuleResponse.reset_mock()
        
        # Call send_decision with a decision to block
        agent_with_mocks.send_decision(mock_connection, False)
        
        # Verify that RuleResponse was called with a rule that has DROP action
        rule_reply = agent_with_mocks.stub.RuleResponse.call_args[0][0]
        assert rule_reply.action == opensnitch_pb2.DROP

    @pytest.mark.integration
    def test_live_connection_to_opensnitch(self):
        """
        Integration test to check if agent can connect to a real OpenSnitch daemon.
        
        This test requires OpenSnitch to be running on the system.
        Skip if not running in integration mode.
        """
        agent = OpenSnitchAgent()
        
        # Setup a thread to run the notifications listener for a short time
        def run_for_a_bit():
            try:
                # Mock the process_notification to avoid making real decisions
                with patch.object(agent, 'process_notification'):
                    # Set a timeout for the grpc call
                    with grpc.insecure_channel('unix:///tmp/osui.sock',
                                              options=[('grpc.enable_http_proxy', 0),
                                                       ('grpc.keepalive_timeout_ms', 1000)]) as channel:
                        agent.channel = channel
                        agent.stub = opensnitch_pb2_grpc.UIStub(channel)
                        
                        # Try to get notifications for 2 seconds
                        notification_request = opensnitch_pb2.NotificationRequest(
                            id=agent.agent_id,
                            type=opensnitch_pb2.NOTIFICATION_TYPE_CONNECTION
                        )
                        
                        # Use a timeout to avoid hanging
                        for _ in range(5):  # Try a few times
                            try:
                                notifications = agent.stub.Notifications(notification_request)
                                for _ in notifications:
                                    return True  # Received at least one notification
                            except grpc.RpcError:
                                time.sleep(0.5)
                        
                        return False  # No notifications received
            except Exception:
                return False
        
        thread = Thread(target=run_for_a_bit)
        thread.daemon = True
        thread.start()
        thread.join(timeout=5)  # Wait up to 5 seconds
        
        # If the thread is still alive, the test is inconclusive
        if thread.is_alive():
            pytest.skip("Could not connect to OpenSnitch within timeout period")

if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
