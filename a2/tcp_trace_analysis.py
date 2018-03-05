"""
tcp_trace_analysis.py

Author: AJ Po-Deziel
Created on: 2018-02-02

Analyzes a packet capture file (pcap), and prints out respective statistics.

Utilizes the dpkt open source module.
Source code: https://github.com/kbandla/dpkt
Documentation: https://dpkt.readthedocs.io/en/latest/
"""

import datetime
import dpkt
import socket
import sys
import tcp_connection


def new_tcp_connection(timestamp, tcp, syn, syn_flag, ack_flag, fin, fin_flag,
                       rst_flag, reset_status):
    """
    Create a new TCPConnection object for use in connections dictionary
    at respective connection tuple.

    :param timestamp: Timestamp of packet
    :param tcp: TCP packet
    :param syn: SYN count
    :param syn_flag: Presence of SYN flag in packet
    :param ack_flag: Presence of ACK flag in packet
    :param fin: FIN count
    :param fin_flag: Presence of FIN flag in packet
    :param rst_flag: Presence of RST flag in packet
    :param reset_status: Indication if connection has ever been reset
    :return: new TCPConnection object
    """
    packets_sent = []
    packets_received = []
    window_sizes = []
    sequence_num = {}
    rtt = []
    start_timestamp = None

    # Retrieve info from TCP packet
    tcp_data = tcp.data
    tcp_window = tcp.win

    packet_timestamp = datetime.datetime.utcfromtimestamp(timestamp)

    if syn_flag:
        # First SYN encounter
        syn = 1
        # 'sequence number': 'timestamp' key-value pair to dict
        sequence_num[tcp.seq] = packet_timestamp
        # Get packet's timestamp
        start_timestamp = packet_timestamp
        packets_sent.append(tcp_data)
    if ack_flag:
        packets_sent.append(tcp_data)
        rtt.append(packet_timestamp)
    if fin_flag:
        fin = 1
        packets_received.append(tcp_data)
    if rst_flag:
        reset_status = True
        packets_received.append(tcp_data)

    # Get window size from TCP header
    window_sizes.append(tcp_window)

    return tcp_connection.TCPConnection(syn_count=syn,
                                        fin_count=fin,
                                        sequence_encountered=sequence_num,
                                        rtt=[],
                                        reset_flag=reset_status,
                                        start_time=start_timestamp,
                                        end_time=None,
                                        window_sizes=window_sizes,
                                        sent_packets=packets_sent,
                                        recvd_packets=packets_received)


def tcp_rtt_analysis(sequence_nums, ack_num, ack_timestamp):
    """
    Perform Round Trip Time (RTT) analysis of packet in connection
    upon reception of packet with ACK flag.
    :param sequence_nums: List of sequence numbers sent out
    :param ack_num: Acknowledgement number in current TCP packet
    :param ack_timestamp: Timestamp on current TCP packet with ACK flag
    :return: Round trip time in seconds
    """
    for sequence in [*sequence_nums]:
        # If Acknowledgement Number is 1 more than any of the sequence numbers
        # in connection, a Round Trip has been completed.
        if sequence + 1 == ack_num:
            ack_time = datetime.datetime.utcfromtimestamp(ack_timestamp)
            raw_rtt = ack_time - sequence_nums[sequence]
            return raw_rtt.total_seconds()
        else:
            continue


def tcp_connection_analysis(packet_capture):
    """
    Analyze packet capture file, and organize into dictionary with
    connection tuple as key and TCPConnection class object as value.
    :param packet_capture: Packet capture file opened by reader
    :return: dictionary of connections
    """
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

        # Default TCP state counter value
        syn = 0
        fin = 0
        reset_status = False

        # If connections dict is empty, add initial key-value pair.
        if bool(connections) is False:
            # New connection, initiate as such.
            connections[connection_tuple] = new_tcp_connection(timestamp, tcp, syn, syn_flag,
                                                               ack_flag, fin, fin_flag, reset_status, rst_flag)

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
                # Evaluate RTT
                rtt = tcp_rtt_analysis(value.sequence_encountered, tcp.ack, timestamp)
                if rtt is not None:
                    value.rtt.append(rtt)
            if fin_flag:
                value.fin_count += 1
                value.recvd_packets.append(tcp.data)
                value.end_time = datetime.datetime.utcfromtimestamp(timestamp)
            if rst_flag:
                value.reset_flag = True
                value.recvd_packets.append(tcp.data)

            # Add packet window size to list
            value.window_sizes.append(tcp.win)

            # Add value back to respective connection_tuple key to update connections dict
            connections[connection_tuple] = value

            # Update reverse connection key-value pair
            if reverse_connection_tuple in connections.keys():
                value = connections[reverse_connection_tuple]
                if syn_flag:
                    if value.syn_count < 1:
                        value.start_time = datetime.datetime.utcfromtimestamp(timestamp)
                    value.syn_count += 1
                    value.recvd_packets.append(tcp.data)
                if ack_flag:
                    value.recvd_packets.append(tcp.data)
                    rtt = tcp_rtt_analysis(value.sequence_encountered, tcp.ack, timestamp)
                    if rtt is not None:
                        value.rtt.append(rtt)
                if fin_flag:
                    value.fin_count += 1
                    value.sent_packets.append(tcp.data)
                    value.end_time = datetime.datetime.utcfromtimestamp(timestamp)
                if rst_flag:
                    value.reset_flag = True
                    value.recvd_packets.append(tcp.data)

                # Add packet window size to list
                value.window_sizes.append(tcp.win)

                # Add value back to respective reverse_connection_tuple key to update connections dict
                connections[reverse_connection_tuple] = value
            elif reverse_connection_tuple not in connections.keys():
                connections[reverse_connection_tuple] = new_tcp_connection(timestamp, tcp, syn, syn_flag, ack_flag,
                                                                           fin, fin_flag, reset_status, rst_flag)

        else:
            # New connection, initiate as such
            connections[connection_tuple] = new_tcp_connection(timestamp, tcp, syn, syn_flag,
                                                               ack_flag, fin, fin_flag, reset_status, rst_flag)

    return connections


def main():
    # Verify command line if argument is passed
    if len(sys.argv) < 2:
        raise Exception("No argument provided. Please provide a packet capture file for analysis.")
        sys.exit(0)

    # Open capture file and read packets
    capture_file = open(sys.argv[1], 'rb')
    packet_capture = dpkt.pcap.Reader(capture_file)

    # Analyze TCP packet capture file
    # Organize into dictionary of connection tuple(key)-TCPConnection(value) pairs
    connections = tcp_connection_analysis(packet_capture)

    # TCP Traffic Analysis - Output
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
    connect_count = 0

    # Dict for tracking complete connections
    complete_connections = {}

    for ip_tuple, connect_item in connections.items():
        connect_count += 1
        """
        If Source IP, Destination IP, Source Port, Dest Port are all unique,
        they indicate a new connection.
        """
        print("Connection {0}".format(connect_count))
        print("Source Address: {0}".format(ip_tuple[0]))
        print("Destination Address: {0}".format(ip_tuple[2]))
        print("Source Port: {0}".format(ip_tuple[1]))
        print("Destination Port: {0}".format(ip_tuple[3]))

        # Output the following if connection is complete
        if connect_item.tcp_complete() is True:
            complete_count += 1
            complete_connections[ip_tuple] = connect_item

            if connect_item.reset_flag is True:
                print("Status: S{0}F{1} + R".format(connect_item.syn_count, connect_item.fin_count))
            elif connect_item.reset_flag is False:
                print("Status: S{0}F{1}".format(connect_item.syn_count, connect_item.fin_count))
            print("Start time: {0}".format(connect_item.start_time))
            print("End time: {0}".format(connect_item.end_time))
            print("Duration: {0} seconds".format(connect_item.duration()))
            print("Number of packets sent from Source to Destination: {0}".format(connect_item.packets_sent_count()))
            print("Number of packets sent from Destination to Source: {0}".format(connect_item.packets_recvd_count()))
            print("Total number of packets: {0}".format(connect_item.total_packet_count()))
            print("Number of data bytes sent from Source to Destination: {0}".format(connect_item.bytes_sent()))
            print("Number of data bytes sent from Destination to Source: {0}".format(connect_item.bytes_received()))
            print("Total number of data bytes: {0}".format(connect_item.bytes_sent() + connect_item.bytes_received()))

        print("END")
        print("+++++++++++++++++++++++++++++++++")

        # If status is reset, then add to reset counter.
        if connect_item.reset_flag is True:
            reset_count += 1

        if (connect_item.syn_count <= 1 and connect_item.fin_count == 0) \
                or (connect_item.syn_count == 0 and connect_item.fin_count <= 1):
            open_count += 1

    print("\n")
    print("-------------------------------------------------")
    print("\n")

    print("C) General: ")
    print("\n")
    print("Total number of complete TCP connections: {0}".format(complete_count))
    print("Number of reset TCP connections: {0}".format(reset_count))
    print("Number of TCP connections that were still open when the trace capture ended: {0}".format(open_count))

    print("\n")
    print("-------------------------------------------------")
    print("\n")

    print("D) Complete TCP Connections:")
    print("\n")

    connection_durations = []
    connection_rtt = []
    connection_packets = []
    connection_windows = []

    # Retrieve duration, total packets, window sizes from each connection
    for ip_tuple, connect_item in complete_connections.items():
        connection_durations.append(connect_item.duration())
        connection_rtt.extend(connect_item.rtt)
        connection_packets.append(connect_item.total_packet_count())
        connection_windows.extend(connect_item.window_sizes)

    # Put connection durations, RTT, packet sizes, window sizes
    # in order from shortest to longest
    connection_durations.sort()
    connection_rtt.sort()
    connection_packets.sort()
    connection_windows.sort()

    # Get mean time duration for complete connections
    duration_sum = sum(connection_durations)
    mean_duration = duration_sum / len(connection_durations)

    # Get mean RTT for complete connections
    rtt_sum = sum(connection_rtt)
    mean_rtt = rtt_sum / len(connection_rtt)

    # Get mean packet count for complete connections
    packet_sum = sum(connection_packets)
    mean_packet_count = packet_sum / len(connection_packets)

    # Get mean window size for complete connections
    window_sum = sum(connection_windows)
    mean_window_size = window_sum / len(connection_windows)

    print("Minimum time duration: {0} seconds".format(connection_durations[0]))
    print("Mean time duration: {0:.6f} seconds".format(mean_duration))
    print("Maximum time duration: {0} seconds".format(connection_durations[-1]))

    print("\n")

    print("Minimum RTT values including both send/received: {0:.6f} seconds".format(connection_rtt[0]))
    print("Mean RTT values including both send/received: {0:.6f} seconds".format(mean_rtt))
    print("Maximum RTT values including both send/received: {0:.6f} seconds".format(connection_rtt[-1]))

    print("\n")

    print("Minimum number of packets including both send/received: {0}".format(connection_packets[0]))
    print("Mean number of packets including both send/received: {0:.6f}".format(mean_packet_count))
    print("Maximum number of packets including both send/received: {0}".format(connection_packets[-1]))

    print("\n")

    print("Minimum receive window sizes including both send/received: {0}".format(connection_windows[0]))
    print("Mean receive window sizes including both send/received: {0:.6f}".format(mean_window_size))
    print("Maximum receive window sizes including both send/received: {0}".format(connection_windows[-1]))

    print("-------------------------------------------------")


if __name__ == '__main__':
    main()
