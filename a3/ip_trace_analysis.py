"""
ip_trace_analysis.py

Author: AJ Po-Deziel
Created on: 2018-03-12

Run IP Trace Analysis from IP datagrams gathered via traceroute.
"""

import ip_connection
import datetime
import dpkt
import statistics
import sys


def main():
    if len(sys.argv) < 2:
        raise Exception("No argument provided. Please include an IP traceroute file for analysis.")

    # Read traceroute file
    capture_file = open(sys.argv[1], 'rb')
    packet_capture = dpkt.pcap.Reader(capture_file)

    ip_packets = []

    # Analyze traceroute file
    for timestamp, raw_packet in packet_capture:
        eth = dpkt.ethernet.Ethernet(raw_packet)
        ip = eth.data

        # Common packet info
        ip_src = ip.src
        ip_dest = ip.dest
        packet_timestamp = datetime.datetime.utcfromtimestamp(timestamp)

        # If packet is ICMP, handle as Windows packet
        if isinstance(ip.data, dpkt.icmp.ICMP):
            if ip.ttl >= 1:
                icmp = ip.data
                ip_packets.append()
        # If packet is UDP, handle as Linux packet
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            port_src = udp.sport
            port_dest = udp.dport
        else:
            continue



    # TODO: IP Protocol Analysis - Output
    # print("The IP address of the source node: " + source_ip)
    # print("The IP address of ultimate destination node: " + dest_ip )
    # print("The IP addresses of the intermediate destination nodes: ")
    # print("Router #")
    #
    # print("The values in the protocol field of IP headers: ")
    # print("id: ")
    # print("id: ")
    #
    # print("\n")
    #
    # print("The number of fragments created from the original datagram is: ")
    # print("The avg RRT between {0} and {1} is: {2}, the s.d. is: {3}".format(source_ip, dest_ip, avg_rtt, sd_rtt))

    print("\n")


if __name__ == '__main__':
    main()