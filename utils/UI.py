from numpy.random import random
from threading import Event, Lock
from typing import Optional

from .DecisionStructure import Actions
from .OpensnitchInterface import OpenSnitchConnection


class AgenTUI:
    """Basic Text User interface for OpenSnitch policy"""

    def __init__(self):
        self.pending_requests = {}
        self.response_lock = Lock()
        self.response_event = Event()
        self.response = None

    def ask_user(self, connection: OpenSnitchConnection) -> int:
        """
        Display connection information to user and get a decision

        Args:
            connection: The connection to show to the user

        Returns:
            int: User-selected action
        """
        # In a real implementation, this would show a GUI dialog
        # For this example, we'll just print to console and get input

        print("\n" + "=" * 60)
        print(f"OpenSnitch Connection Request:")
        print("-" * 60)
        print(f"Process: {connection.process_path} (PID: {connection.pid})")
        print(
            f"Destination: {connection.dst_host if connection.dst_host else connection.dst_ip}:{connection.dst_port}"
        )
        print(f"Protocol: {connection.protocol}")
        print(f"User ID: {connection.user_id}")
        print("-" * 60)
        print("Actions:")
        print("0: Allow Once")
        print("1: Allow Until App Quits")
        print("2: Allow Always")
        print("3: Block Once")
        print("4: Block Until App Quits")
        print("5: Block Always")
        print("-" * 60)

        while True:
            try:
                action = int(input("Enter action number (0-5): ").strip())
                if 0 <= action <= 5:
                    return action
                print("Invalid action. Please enter a number between 0 and 5.")
            except ValueError:
                print("Invalid input. Please enter a number.")

    def get_feedback(
        self, connection: OpenSnitchConnection, action: int
    ) -> Optional[bool]:
        """
        Ask user for feedback on an automatically taken action

        Args:
            connection: The connection
            action: The action that was taken

        Returns:
            bool or None: True if user approves, False if disapproves, None if no feedback
        """
        # In a real implementation, this might be a non-intrusive notification
        # For this example, we'll randomly decide whether to ask for feedback
        if random() < 0.1:  # Only ask 10% of the time to avoid bothering the user
            print("\n" + "-" * 60)
            print(
                f"Feedback Request for {connection.process_path} → {connection.dst_host if connection.dst_host else connection.dst_ip}"
            )
            print(f"Action taken: {Actions.to_str(action)}")
            response = (
                input("Was this the right decision? (y/n/[skip]): ").strip().lower()
            )
            if response == "y":
                return True
            elif response == "n":
                return False
        return None


class TrueFeedback:
    """Mock user interface for agent training"""

    def __init__(self):
        self.pending_requests = {}
        self.response_lock = Lock()
        self.response_event = Event()
        self.response = None
        self.good_applications = get_destinations('data/good_applications.yaml')
        self.good_destinations = get_destinations('data/good_destinations.yaml')

    def ask_user(self, connection: OpenSnitchConnection) -> int:
        """
        Select action based on ground truth

        Args:
            connection: The connection to show

        Returns:
            int: Auto-selected action
        """

        # print("Actions:")
        # print("0: Allow Once")
        # print("1: Allow Until App Quits")
        # print("2: Allow Always")
        # print("3: Block Once")
        # print("4: Block Until App Quits")
        # print("5: Block Always")
        # print("-" * 60)

        return randint(0, 5)

    def get_feedback(
        self, connection: OpenSnitchConnection, action: int
    ) -> Optional[bool]:
        """
        True feedback on an automatically taken action

        Args:
            connection: The connection
            action: The action that was taken

        Returns:
            bool or None: True if user approves, False if disapproves, None if no feedback
        """

        if connection.destination in self.good_destinations \
                and connection.application in self.good_applications \
                and action in (0, 1, 2):
            return True
        elif connection.destination in self.bad_destinations \
                and connection.application in self.bad_applications \
                and action in (2, 3, 4):
            return True
        else:
            return False
