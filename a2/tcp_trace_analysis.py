"""
tcp_trace_analysis.py

Author: AJ Po-Deziel
Created on: 2018-02-02

Analyzes a packet capture file (pcap), and prints out respective stats.

https://github.com/jeffsilverm/dpkt_doc/blob/master/decode_tcp.py

"""

import dpkt
import socket
import sys
import tcp_connection


# TODO: Analyze TCP Connection for a given packet
def tcp_connection_analysis():
    return None

def main():
    # Verify command line if argument is passed
    if len(sys.argv) < 2:
        raise Exception("No argument provided. Please provide a packet capture file for analysis.")
        sys.exit(0)

    # Open capture file and read packets
    capture_file = open(sys.argv[1], 'rb')
    packet_capture = dpkt.pcap.Reader(capture_file)

    connections = {}

    # Tracker variables for Part C - General output
    complete_connections = 0
    reset_connections = 0
    open_connections = 0

    # Retrieve TCP data from within packet
    for header, raw_packet in packet_capture:

        eth = dpkt.ethernet.Ethernet(raw_packet)
        ip = eth.data

        # Verify for existence of TCP packets, exclude HTTP
        # If TCP, retrieve and increase packet_count.
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp = ip.data
        else:
            continue

        # Get source & destination IP addresses from packet
        src_addr = socket.inet_ntoa(ip.src)
        dest_addr = socket.inet_ntoa(ip.dst)

        # Get source & destination connection ports from packet
        src_port = tcp.sport
        dest_port = tcp.dport

        connection_tuple = (str(src_addr), str(src_port), str(dest_addr), str(dest_port))

        # Get TCP Flags
        # Sourced from http://engineering-notebook.readthedocs.io/en/latest/engineering/dpkt.html
        syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
        fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
        rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0

        syn = 0
        fin = 0
        rst = 0

        # Does connection tuple exist as key in dictionary?
        # If not, create.
        if str(connection_tuple) in connections.keys():
            connections[connection_tuple].update(None, None)
        else:
            if syn_flag:
                syn = 1
            if fin_flag:
                fin = 1

            connections[connection_tuple] = tcp_connection.TCPConnection(syn_count=syn, fin_count=fin)


    # TODO: TCP Traffic Analysis - Output
    # print("A) Total number of connections: " + len(connections.keys()) )
    #
    # print("\n")
    # print("_________________________________________________")
    # print("\n")
    #
    # print("B) Connections' details: ")
    # for ip_tuple, connect_item in connections.items():
    #     """
    #     If Source IP, Destination IP, Source Port, Dest Port are all unique,
    #     they indicate a new connection.
    #     """
    #     print("Connection " + str(i))
    #     print("Source Address: " + ip_tuple[0])
    #     print("Destination Address: " + ip_tuple[2])
    #     print("Source Port: " + ip_tuple[1])
    #     print("Destination Port: " + ip_tuple[3])
    #
    #     # Output the following if connection is complete
    #     if status is True:
    #         print("Status: ")
    #         print("Start time: ")
    #         print("End time: ")
    #         print("Duration: ")
    #         print("Number of packets sent from Source to Destination: ")
    #         print("Number of packets sent from Destination to Source: ")
    #         print("Total number of packets: ")
    #         print("Number of data bytes sent from Source to Destination: ")
    #         print("Number of data bytes sent from Destination to Source: ")
    #         print("Total number of data bytes: ")
    #         print("END")
    #
    #     if
    #         print("+++++++++++++++++++++++++++++++++")
    #
    # print("\n")
    # print("_________________________________________________")
    # print("\n")
    #
    # print("C) General: ")
    # print("\n")
    # print("Total number of complete TCP connections: ")
    # print("Number of reset TCP connections: ")
    # print("Number of TCP connections that were still open when the trace capture ended: ")
    #
    # print("\n")
    # print("_________________________________________________")
    # print("\n")
    #
    # print("D) Complete TCP Connections:")
    # print("\n")
    #
    # print("Minimum time duration: ")
    # print("Mean time duration: ")
    # print("Maximum time duration: ")
    #
    # print("\n")
    #
    # print("Minimum RTT values including both send/received: ")
    # print("Mean RTT values including both send/received: ")
    # print("Maximum RTT values including both send/received: ")
    #
    # print("\n")
    #
    # print("Minimum number of packets including both send/received: ")
    # print("Mean number of packets including both send/received: ")
    # print("Maximum number of packets including both send/received: ")
    #
    # print("\n")
    #
    # print("Minimum receive window sizes including both send/received: ")
    # print("Mean receive window sizes including both send/received: ")
    # print("Maximum receive window sizes including both send/received: ")
    #
    # print("_________________________________________________")


if __name__ == '__main__':
    main()
