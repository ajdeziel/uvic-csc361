"""
tcp_trace_analysis.py

Author: AJ Po-Deziel
Created on: 2018-02-02

Analyzes a packet capture file (pcap), and prints out respective stats.
"""

import dpkt
import io
import pcapy
import sys
import tcp_connection

def read_from_binary(file):
    return None


def main():

    if len(sys.argv) < 2:
        raise Exception("No argument provided. Please a packet capture file for analysis.")
        sys.exit(0)


    capture_file = open(sys.argv[1])
    packet_capture = dpkt.pcap.Reader(capture_file)

    for header, raw_packet in packet_capture:
        eth = dpkt.ethernet.Ethernet(raw_packet)
        ip = eth.data
        tcp = ip.data

        tcp_packet = tcp_connection.TCPConnection(None, tcp.sport, None, tcp.dport)
        print(tcp_packet)


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
    # print("Total number of connections: ")
    #
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


if __name__ == '__main__':
    main()
