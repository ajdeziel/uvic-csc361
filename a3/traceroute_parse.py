"""
traceroute_parse.py

Author: AJ Po-Deziel
Created on: 2018-03-23

Data structure to store parsed packet from traceroute capture.
"""
class TraceroutePacket:
    def __init__(self, src_ip, dest_ip, timestamp, protocol, data):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.timestamp = timestamp
        self.protocol = protocol
        self.data = data

    def get_ip(self, ip_type):
        """
        Get source or destination source IP address.
        :param ip_type: Specified IP address location (src or dest)
        :return: IP address
        """
        if ip_type is "src":
            return self.src_ip
        elif ip_type is "dest":
            return self.dest_ip
        else:
            raise Exception("Incorrect IP location.")
