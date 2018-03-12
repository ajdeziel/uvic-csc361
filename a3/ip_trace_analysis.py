"""
ip_trace_analysis.py

Author: AJ Po-Deziel
Created on: 2018-03-12

Run IP Trace Analysis from IP datagrams gathered via traceroute.
"""

import dpkt
import sys


def main():
    if len(sys.argv) < 2:
        raise Exception("No argument provided. Please include an IP traceroute file for analysis.")

    # Read traceroute file
    capture_file = open(sys.argv[1], 'rb')
    eth = dpkt.pcap.Reader(capture_file)

    # Analyze traceroute file

    # TODO: IP Protocol Analysis - Output
    print("The IP address of the source node: ")
    print("The IP address of ultimate destination node: ")
    print("The IP addresses of the intermediate destination nodes: ")
    print("Router #")

    print("The values in the protocol field of IP headers: ")
    print("id: ")
    print("id: ")

    print("\n")

    print("The number of fragments created from the original datagram is: ")
    print("The avg RRT between (src IP) and (dest IP) is: (time), the s.d. is: (time)")

    print("\n")


if __name__ == '__main__':
    main()