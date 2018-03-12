"""
ip_connection.py

Author: AJ Po-Deziel
Created on: 2018-03-12

Data structure to store IP connection data.
"""

class IPConnection():
    def __init__(self, src_ip, dest_ip, protocol):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.protocol = protocol