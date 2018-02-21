"""
tcp_trace_analysis.py

Author: AJ Po-Deziel
Created on: 2018-02-02

Analyzes a packet capture file (pcap), and prints out respective stats.

https://github.com/jeffsilverm/dpkt_doc/blob/master/decode_tcp.py
http://engineering-notebook.readthedocs.io/en/latest/engineering/dpkt.html
"""

import dpkt
import io
import pcapy
import socket
import sys
import tcp_connection


def main():
    # Verify command line if argument is passed
    if len(sys.argv) < 2:
        raise Exception("No argument provided. Please provide a packet capture file for analysis.")
        sys.exit(0)

    # Full steam ahead!
    capture_file = open(sys.argv[1], 'rb')
    packet_capture = dpkt.pcap.Reader(capture_file)

    packet_count = 0

    # Retrieve TCP data from within packet
    for header, raw_packet in packet_capture:
        packet_count += 1

        eth = dpkt.ethernet.Ethernet(raw_packet)
        ip = eth.data

        # Verify for existence of TCP packets, exclude HTTP
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

        # Get TCP Flags
        syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
        fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
        rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0

        #tcp_packet = tcp_connection.TCPConnection( tcp.sport, None, tcp.dport)
        #print(tcp_packet)

        # print(tcp.data)
        print(str(src_addr) + ":" + str(src_port) + ", " + str(dest_addr) + ":" + str(dest_port))

    print(packet_count)


    # capture_file = pcapy.open_offline(sys.argv[1])
    # header, raw_packet_bytes = capture_file.next()
    #
    # while header is not None:
    #     packet = io.BytesIO(raw_packet_bytes)
    #
    #
    #
    #     header, raw_packet_bytes = capture_file.next()
    #
    # # Use a stream to read packet (BytesIO is my friend - but Charlie is too.)
    # for packet in packets:
    #     packet_decoded = bytes(packet).hex()
    #     print(packet_decoded)

    # TCP Traffic Analysis - Output
    # print("A) Total number of connections: ")
    #
    # print("\n")
    # print("_________________________________________________")
    # print("\n")
    #
    # print("B) Connections' details: ")
    # for connect_item in connections:
    #     """
    #     If Source IP, Destination IP, Source Port, Dest Port are all unique,
    #     they indicate a new connection.
    #     """
    #     print("Connection " )
    #     print("Source Address: ")
    #     print("Destination Address: ")
    #     print("Source Port: ")
    #     print("Destination Port: ")
    #
    #     if status is valid:
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
    # print("D) Complete TCP Connections: ")
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
