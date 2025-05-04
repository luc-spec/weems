#!/usr/bin/env python3
import sqlite3
import time
import sys
from time import time
from datetime import datetime
from logging import getLogger
from numpy.random import choice, randint

from utils.OpensnitchInterface import OpenSnitchConnection

logger = getLogger("agent")


class OpenSnitchPlayback:
    def __init__(self, db_path, callback=None, time_scale=1.0, limit=None, verbose=False):
        """
        Initialize the OpenSnitch event simulator.
        
        Args:
            db_path (str): Path to the OpenSnitch SQLite database
            time_scale (float): Speed factor for playback (1.0 = real-time, 2.0 = double speed)
            limit (int): Maximum number of events to replay (None for all)
            verbose (bool): Whether to print detailed event information
        """
        self.db_path = db_path
        self.time_scale = time_scale
        self.limit = limit
        self.verbose = verbose
        self.connections = []
        self.conn = None
        self.cursor = None

        if self.connect_to_db():
            self.load_events()
    
    def connect_to_db(self):
        """Connect to the OpenSnitch SQLite database."""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            self.cursor = self.conn.cursor()
            return True
        except sqlite3.Error as e:
            print(f"Database connection error: {e}", file=sys.stderr)
            return False
    
    def load_events(self):
        """
        Load connection events from the database.
        
        OpenSnitch typically stores connection events in a 'connections' table,
        but the exact schema might vary between versions.
        """
        try:
            # First, let's inspect the database schema to find the right table
            self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [table[0] for table in self.cursor.fetchall()]
            
            if 'connections' in tables:
                table_name = 'connections'
            elif 'connection' in tables:
                table_name = 'connection'
            else:
                # Try to find a table that might contain connection data
                for table in tables:
                    if 'connect' in table.lower():
                        table_name = table
                        break
                else:
                    raise ValueError("Could not find a connections table in the database")
            
            # Get column information for the table
            self.cursor.execute(f"PRAGMA table_info({table_name})")
            columns = [column[1] for column in self.cursor.fetchall()]
            
            # Build a query based on available columns
            query = f"SELECT * FROM {table_name}"
            if self.limit:
                query += f" LIMIT {self.limit}"
            
            # Execute query and process results
            self.cursor.execute(query)
            rows = self.cursor.fetchall()
            
            # Map database columns to OpenSnitchConnection attributes
            for row in rows:
                conn = OpenSnitchConnection()
                
                # Map common column names (adjust based on actual schema)
                for column in columns:
                    col_lower = column.lower()
                    value = row[column]
                    
                    if 'process' in col_lower and 'path' in col_lower:
                        conn.process_path = value
                    elif col_lower == 'pid' or col_lower == 'process_id':
                        conn.pid = value if value else 0
                    elif col_lower == 'dst_ip' or col_lower == 'dst_addr' or col_lower == 'remote_addr':
                        conn.dst_ip = value
                    elif col_lower == 'dst_host' or col_lower == 'host':
                        conn.dst_host = value
                    elif col_lower == 'dst_port' or col_lower == 'port':
                        conn.dst_port = value if value else 0
                    elif col_lower == 'protocol' or col_lower == 'proto':
                        conn.protocol = value
                    elif col_lower == 'user_id' or col_lower == 'uid':
                        conn.user_id = value if value else 0
                    elif 'time' in col_lower and ('stamp' in col_lower or 'stamp' in col_lower):
                        # Try to parse timestamp
                        try:
                            if isinstance(value, (int, float)):
                                conn.timestamp = float(value)
                            elif isinstance(value, str):
                                # Try to parse datetime string to timestamp
                                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                                conn.timestamp = dt.timestamp()
                        except (ValueError, TypeError):
                            # If timestamp parsing fails, just use the index as a sequence
                            pass
                
                self.connections.append(conn)
            
            # If we couldn't parse timestamps, use sequence numbers
            if any(conn.timestamp == 0 for conn in self.connections):
                first_time = time()
                for i, conn in enumerate(self.connections):
                    # Assign timestamps spaced 1 second apart
                    conn.timestamp = first_time + i
            
            # Sort connections by timestamp
            self.connections.sort(key=lambda x: x.timestamp)
            
            print(f"Loaded {len(self.connections)} connection events")
            return True
            
        except sqlite3.Error as e:
            print(f"Error loading events: {e}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            return False
    
    def simulate(self):
        """
        Simulate connection events with proper timing.
        
        Args:
            event_callback (callable): Optional callback function that takes an OpenSnitchConnection
                                      object as an argument, called for each event.
        """
        if not self.connections:
            print("No connections to simulate", file=sys.stderr)
            return
        
        print(f"Starting simulation with time scale factor: {self.time_scale}")
        
        start_time = time()
        first_event_time = self.connections[0].timestamp
        
        for i, conn in enumerate(self.connections):
            # Calculate when this event should happen in simulation time
            event_delay = (conn.timestamp - first_event_time) / self.time_scale
            
            # Calculate how long to wait from now
            #elapsed = time() - start_time
            #wait_time = max(0, event_delay - elapsed)
            
            #if wait_time > 0:
            #    time.sleep(wait_time)
            
            # Process the event
            if self.verbose:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Event {i+1}/{len(self.connections)}: "
                      f"{conn.process_path} (PID: {conn.pid}) → {conn.dst_host or conn.dst_ip}:{conn.dst_port} "
                      f"[{conn.protocol}] (User: {conn.user_id})")
            
            # Call the callback if provided
            if self.callback and callable(self.callback):
                self.callback(conn)
        
        print(f"Simulation completed. Replayed {len(self.connections)} events in "
              f"{time() - start_time:.2f} seconds.")

