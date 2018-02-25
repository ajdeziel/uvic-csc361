"""
tcp_trace_analysis.py

Author: AJ Po-Deziel
Created on: 2018-02-02

Analyzes a packet capture file (pcap), and prints out respective stats.

https://github.com/jeffsilverm/dpkt_doc/blob/master/decode_tcp.py

"""

import datetime
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

    # Retrieve TCP data from within packet
    for timestamp, raw_packet in packet_capture:

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
        reverse_connection_tuple = (str(dest_addr), str(dest_port), str(src_addr), str(src_port))

        # Get TCP Flags
        # Sourced from http://engineering-notebook.readthedocs.io/en/latest/engineering/dpkt.html
        syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
        ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
        fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
        rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0

        # TODO: Fix connections.keys() for loop. Will not enter at all because it is empty at first.
        # STATUS: ALMOST DONE, gotta work out complete connections.

        # TODO: Fix by doing packet parsing outside, and then adding to/updating respective dictionary key-value pair.

        # Default TCP state counter value
        syn = 0
        fin = 0

        # If connections dict is empty, add initial key-value pair.
        if bool(connections) is False:
            packets_sent = []
            packets_received = []

            if syn_flag:
                # First SYN encounter
                syn = 1
                # Get packet's timestamp
                start_timestamp = datetime.datetime.utcfromtimestamp(timestamp)
                packets_sent.append(tcp.data)
            if ack_flag:
                packets_sent.append(tcp.data)
            if fin_flag:
                fin = 1
                packets_received.append(tcp.data)
            if rst_flag:
                syn = 0
                fin = 0

            connections[connection_tuple] = tcp_connection.TCPConnection(syn_count=syn,
                                                                         fin_count=fin,
                                                                         start_time=start_timestamp,
                                                                         end_time=None,
                                                                         sent_packets=packets_sent,
                                                                         recvd_packets=packets_received)

        # Does connection tuple exist as key in dictionary?
        # If not, create.
        if connection_tuple in connections.keys():
            value = connections[connection_tuple]
            if syn_flag:
                # If we haven't encounter a SYN connection, get timestamp as start_time
                if value.syn_count < 1:
                    value.start_time = datetime.datetime.utcfromtimestamp(timestamp)
                value.syn_count += 1
                value.sent_packets.append(tcp.data)
            if ack_flag:
                value.sent_packets.append(tcp.data)
            if fin_flag:
                value.fin_count += 1
                value.recvd_packets.append(tcp.data)
                value.end_time = datetime.datetime.utcfromtimestamp(timestamp)
            if rst_flag:
                value.syn_count = 0
                value.fin_count = 0

            if connection_tuple in connections.keys():
                value.sent_packets.append(tcp.data)
            elif reverse_connection_tuple in connections.keys():
                value = connections[reverse_connection_tuple]
                if syn_flag:
                    if value.syn_count < 1:
                        value.start_time = datetime.datetime.utcfromtimestamp(timestamp)
                    value.syn_count += 1
                    value.recvd_packets.append(tcp.data)
                if ack_flag:
                    value.recvd_packets.append(tcp.data)
                if fin_flag:
                    value.fin_count += 1
                    value.sent_packets.append(tcp.data)
                    value.end_time = datetime.datetime.utcfromtimestamp(timestamp)
                if rst_flag:
                    value.syn_count = 0
                    value.fin_count = 0
                value.recvd_packets.append(tcp.data)
            connections[connection_tuple] = value
        else:
            # New connection, initiate as such
            packets_sent = []
            packets_received = []

            if syn_flag:
                syn = 1
                # Get packet's timestamp
                start_timestamp = datetime.datetime.utcfromtimestamp(timestamp)
                packets_sent.append(tcp.data)
            if ack_flag:
                packets_sent.append(tcp.data)
            if fin_flag:
                fin = 1
                packets_received.append(tcp.data)
            if rst_flag:
                syn = 0
                fin = 0

            connections[connection_tuple] = tcp_connection.TCPConnection(syn_count=syn,
                                                                         fin_count=fin,
                                                                         start_time=start_timestamp,
                                                                         end_time=None,
                                                                         sent_packets=packets_sent,
                                                                         recvd_packets=packets_received)

    # TODO: TCP Traffic Analysis - Output
    print("A) Total number of connections: " + str(len(connections.keys())))

    print("\n")
    print("-------------------------------------------------")
    print("\n")

    print("B) Connections' details: ")
    print("\n")

    # Tracker variables for Part C - General output
    complete_count = 0
    reset_count = 0
    open_count = 0
    i = 0

    for ip_tuple, connect_item in connections.items():
        i += 1
        """
        If Source IP, Destination IP, Source Port, Dest Port are all unique,
        they indicate a new connection.
        """
        print("Connection " + str(i))
        print("Source Address: " + ip_tuple[0])
        print("Destination Address: " + ip_tuple[2])
        print("Source Port: " + ip_tuple[1])
        print("Destination Port: " + ip_tuple[3])

        # Evaluate if connection is complete
        complete_status = connect_item.tcp_complete()

        # Output the following if connection is complete
        if complete_status is True:
            complete_count += 1
            print("Status: S" + str(connect_item.syn_count) + "F" + str(connect_item.fin_count))
            print("Start time: " + str(connect_item.start_time))
            print("End time: " + str(connect_item.end_time))
            print("Duration: " + str(connect_item.duration()))
            print("Number of packets sent from Source to Destination: " + str(connect_item.packets_sent_count()))
            print("Number of packets sent from Destination to Source: " + str(connect_item.packets_recvd_count()))
            print("Total number of packets: " + str(connect_item.total_packet_count()))
            print("Number of data bytes sent from Source to Destination: " + str(connect_item.bytes_sent()))
            print("Number of data bytes sent from Destination to Source: " + str(connect_item.bytes_received()))
            print("Total number of data bytes: " + str(connect_item.bytes_sent() + connect_item.bytes_received()))

        print("END")
        print("+++++++++++++++++++++++++++++++++")

        # if status is reset, then add to reset counter.
        if connect_item.syn_count == 0 and connect_item.fin_count == 0:
            reset_count += 1

        if (connect_item.syn_count <= 1 and connect_item.fin_count == 0) \
                or (connect_item.syn_count == 0 and connect_item.fin_count <= 1):
            open_count += 1

    print("\n")
    print("_________________________________________________")
    print("\n")

    print("C) General: ")
    print("\n")
    print("Total number of complete TCP connections: " + str(complete_count))
    print("Number of reset TCP connections: " + str(reset_count))
    print("Number of TCP connections that were still open when the trace capture ended: " + str(open_count))
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
