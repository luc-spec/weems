from dbus import SystemBus, Interface
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

def setup_opensnitch_listener():
    """Set up OpenSnitch D-Bus listener"""
    try:
        # Connect to OpenSnitch D-Bus interface
        bus = SystemBus()

        opensnitch_object = bus.get_object(
            "io.github.evilsocket.opensnitch",
            "/io/github/evilsocket/opensnitch/rule"
        )

        opensnitch_interface = Interface(
            opensnitch_object,
            "io.github.evilsocket.opensnitch.Rule"
        )

        # Register for connection events
        opensnitch_interface.connect_to_signal(
          "NewConnection", 
          handle_connection
        )

        print("OpenSnitch listener configured successfully")

        # Start the main loop
        loop = GLib.MainLoop()
        loop.run()

    except Exception as e:
        print(f"Error setting up OpenSnitch listener: {e}")

