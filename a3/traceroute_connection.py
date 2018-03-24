"""
traceroute_connection.py

Author: AJ Po-Deziel
Created on: 2018-03-12

Data structure to store IP connection data.
"""

import statistics

class TracerouteConnection():
    def __init__(self, timestamp, protocol, ttl_current):
        self.timestamp = timestamp
        self.protocol = protocol
        self.ttl_current = ttl_current