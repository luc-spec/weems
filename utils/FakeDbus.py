import threading
import random
import time
from collections import namedtuple
from typing import Callable, Dict, Any, Optional, List

# Define a connection event structure
ConnectionEvent = namedtuple('ConnectionEvent', [
    'process_path', 'process_id', 'destination_ip', 'destination_port', 
    'protocol', 'user_id', 'process_args'
])

class DBusSurrogate:
    """
    A surrogate for DBus connections that simulates events and signals
    """
    def __init__(self):
        self._signals: Dict[str, List[Callable]] = {}
        self._running = False
        self._thread = None
        
    def get_object(self, service_name: str, object_path: str) -> 'DBusObjectSurrogate':
        """Simulate getting an object from DBus"""
        print(f"DBus surrogate: Getting object {service_name} at path {object_path}")
        return DBusObjectSurrogate(self, service_name, object_path)
        
    def add_signal_receiver(self, callback: Callable, signal_name: str) -> None:
        """Register a callback for a signal"""
        if signal_name not in self._signals:
            self._signals[signal_name] = []
        self._signals[signal_name].append(callback)
        
    def emit_signal(self, signal_name: str, *args, **kwargs) -> None:
        """Emit a signal to all registered callbacks"""
        if signal_name in self._signals:
            for callback in self._signals[signal_name]:
                callback(*args, **kwargs)
                
    def start_simulation(self, interval_range: tuple = (5, 15)) -> None:
        """Start a thread that simulates network events"""
        if self._running:
            return
            
        self._running = True
        self._thread = threading.Thread(target=self._simulation_loop, args=(interval_range,))
        self._thread.daemon = True
        self._thread.start()
        
    def stop_simulation(self) -> None:
        """Stop the simulation thread"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)
            
    def _simulation_loop(self, interval_range: tuple) -> None:
        """Generate simulated network events periodically"""
        while self._running:
            # Wait a random amount of time before generating the next event
            wait_time = random.uniform(*interval_range)
            time.sleep(wait_time)
            
            # Generate a random connection event
            event = self._generate_random_connection()
            
            # Emit the NewConnection signal
            self.emit_signal("NewConnection", event)
            
    def _generate_random_connection(self) -> ConnectionEvent:
        """Generate a random connection event"""
        processes = [
            ("/usr/bin/firefox", "firefox -private"),
            ("/usr/bin/chromium", "chromium --incognito"),
            ("/usr/bin/curl", "curl https://api.example.com"),
            ("/usr/bin/wget", "wget https://download.example.org/file.zip"),
            ("/usr/bin/python3", "python3 script.py"),
            ("/usr/bin/ssh", "ssh user@server.example.com"),
        ]
        
        # Pick a random process
        process_path, process_args = random.choice(processes)
        
        # Generate a random connection
        return ConnectionEvent(
            process_path=process_path,
            process_id=random.randint(1000, 9999),
            destination_ip=f"192.168.1.{random.randint(1, 254)}",
            destination_port=random.choice([80, 443, 8080, 22, 25, 53]),
            protocol=random.choice(["TCP", "UDP"]),
            user_id=random.randint(1000, 1999),
            process_args=process_args
        )


class DBusObjectSurrogate:
    """Surrogate for a DBus object"""
    def __init__(self, bus: DBusSurrogate, service_name: str, object_path: str):
        self.bus = bus
        self.service_name = service_name
        self.object_path = object_path
        
    def get_dbus_method(self, method_name: str, dbus_interface: Optional[str] = None) -> Callable:
        """Get a surrogate method that can be called"""
        def method_surrogate(*args, **kwargs):
            print(f"Called method {method_name} on {self.service_name} ({dbus_interface})")
            # Simulate method behavior here
            return None
        return method_surrogate


class DBusInterfaceSurrogate:
    """Surrogate for a DBus interface"""
    def __init__(self, obj: DBusObjectSurrogate, interface_name: str):
        self.obj = obj
        self.interface_name = interface_name
        
    def connect_to_signal(self, signal_name: str, callback: Callable) -> None:
        """Connect a callback to a signal"""
        self.obj.bus.add_signal_receiver(callback, signal_name)
        print(f"Connected to signal {signal_name} on interface {self.interface_name}")


# Surrogate for SystemBus
class SystemBusSurrogate(DBusSurrogate):
    """Surrogate for DBus SystemBus"""
    pass


# Function to set up a surrogate OpenSnitch listener
def setup_opensnitch_surrogate_listener(callback_fn: Callable) -> DBusSurrogate:
    """
    Set up a surrogate OpenSnitch DBus listener that simulates connection events
    
    Args:
        callback_fn: Function to call when a new connection is detected
        
    Returns:
        The surrogate bus object that can be used to control the simulation
    """
    try:
        # Create a surrogate system bus
        bus = SystemBusSurrogate()
        
        # Get a surrogate object
        opensnitch_object = bus.get_object(
            "io.github.evilsocket.opensnitch",
            "/io/github/evilsocket/opensnitch/rule"
        )
        
        # Create a surrogate interface
        opensnitch_interface = DBusInterfaceSurrogate(
            opensnitch_object,
            "io.github.evilsocket.opensnitch.Rule"
        )
        
        # Register for connection events
        opensnitch_interface.connect_to_signal("NewConnection", callback_fn)
        
        print("OpenSnitch surrogate listener configured successfully")
        
        # Start the simulation
        bus.start_simulation()
        
        return bus
        
    except Exception as e:
        print(f"Error setting up OpenSnitch surrogate listener: {e}")
        return None


def handle_connection(event):
    """Handle a new connection event"""
    print(f"New FAKE connection:")
    print(f"  Process: {event.process_path} (PID: {event.process_id})")
    print(f"  Destination: {event.destination_ip}:{event.destination_port} ({event.protocol})")
    print(f"  User ID: {event.user_id}")
    print(f"  Args: {event.process_args}")


def setup_opensnitch_listener(handler: callable = handle_connection):
    """
    Set up OpenSnitch D-Bus listener with surrogate implementation
    instead of actual DBus connections
    """
    # Use the surrogate implementation
    bus = setup_opensnitch_surrogate_listener(handler)
    
    # Instead of GLib.MainLoop, we can just use a simple thread wait
    if bus:
        try:
            # This simulates a main loop without actually using GLib
            print("Surrogate listener running. Press Ctrl+C to stop.")
            while True:
                time.sleep(3*random.random())
        except KeyboardInterrupt:
            print("Stopping surrogate listener")
            bus.stop_simulation()
    else:
        print("Failed to set up surrogate listener")


if __name__ == "__main__":
    # Test the surrogate implementation
    setup_opensnitch_listener()
