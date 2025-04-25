from random import randint

def get_dummy_network_load():
    """Get current network load percentage (0-100)"""
    # In a real implementation, measure actual network throughput
    # For simplicity, we'll return a random value here
    return randint(10, 80)

def get_current_network_load(interface=None, interval=1.0, max_bandwidth=None):
    """
    Get current network load percentage (0-100)
    
    Args:
        interface: Specific network interface to measure (None = all interfaces)
        interval: Time in seconds to measure traffic (default=1.0)
        max_bandwidth: Maximum bandwidth in bytes/sec for calculating percentage
                      (None = auto-calculate based on recent peak)
    
    Returns:
        Float representing network utilization percentage (0-100)
    """
    # Get initial bytes count
    initial_counters = psutil.net_io_counters(pernic=True)
    
    # If no specific interface given, sum across all interfaces
    if interface is None:
        initial_bytes = sum(counter.bytes_sent + counter.bytes_recv 
                          for counter in initial_counters.values())
    else:
        if interface not in initial_counters:
            raise ValueError(f"Interface {interface} not found. Available interfaces: {list(initial_counters.keys())}")
        initial_bytes = initial_counters[interface].bytes_sent \
                       + initial_counters[interface].bytes_recv
    
    # Wait for specified interval
    time.sleep(interval)
    
    # Get bytes count after interval
    final_counters = psutil.net_io_counters(pernic=True)
    
    # Calculate bytes during interval
    if interface is None:
        final_bytes = sum(counter.bytes_sent + counter.bytes_recv 
                        for counter in final_counters.values())
    else:
        final_bytes = final_counters[interface].bytes_sent + final_counters[interface].bytes_recv
    
    bytes_per_second = (final_bytes - initial_bytes) / interval
    
    # If max_bandwidth not provided, use a reasonable default or based on recent measurements
    if max_bandwidth is None:
        # Default to 1 Gbps (125 MB/s) or use a dynamic approach
        max_bandwidth = 125 * 1024 * 1024  # 1 Gbps in bytes/sec
    
    # Calculate percentage (cap at 100%)
    percentage = min(100.0, (bytes_per_second / max_bandwidth) * 100)
    
    return percentage
