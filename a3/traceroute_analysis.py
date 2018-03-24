"""
traceroute_analysis.py

Author: AJ Po-Deziel
Created on: 2018-03-12

Run IP Trace Analysis from IP datagrams gathered via traceroute.
"""

import traceroute_connection
import datetime
import dpkt
import socket
import statistics
import sys
import traceroute_parse


def get_ip(packets):
    first_packet = packets[0]
    source_ip = first_packet.get_ip("src")
    dest_ip = first_packet.get_ip("dest")

    return source_ip, dest_ip


def packet_analysis(packets):
    # Cases to consider

    # 1. src->dest: Establish traceroute connection
    # 2. router->src: Oops, did it again and hit a roadblock (i.e. TTL exceeded)
    # 3. dest->src: 2 sub-cases to look at.
    #   a. Linux: Destination unreachable (counterintuitive, reached dest)
    #   b. Win: Echo reply, reached dest.

    filtered_packets = {}
    rtt = []

    # Analyze traceroute file
    for packet in packets:
        src_ip = packet.get_ip("src")
        dest_ip = packet.get_ip("dest")

        ip_tuple = (src_ip, dest_ip)
        # Find the probes, and then map the responses to the respective probes

        if isinstance(packet.data, dpkt.icmp.ICMP):
            if isinstance(packet.data.data, dpkt.udp.UDP):
                # Nested UDP packet, treat as Linux
                pass
            else:
                # Check like Windows packet
                if ip_tuple not in filtered_packets.keys():
                    # Create new key
                    filtered_packets[ip_tuple] = traceroute_connection.TracerouteConnection(packet.timestamp,
                                                                                            packet.protocol)
        elif isinstance(packet.data, dpkt.udp.UDP):
            # UDP packet encountered, treat as Linux
            pass
        else:
            continue

    return filtered_packets


def linux_packet_analysis():
    pass


def windows_packet_analysis():
    pass


def get_router_ip(packet_dict, traceroute_src, traceroute_dest):
    """
    Filter and retrieve list of router IPs encountered in traceroute.
    :param packet_dict: Dictionary of captured packets
    :param traceroute_src: Source IP address
    :param traceroute_dest: Ultimate destination IP address
    :return: List of intermediate router IP addresses encountered
    """

    # Unpack packet_dict and return keys into list literal
    ip_keys = [*packet_dict]
    router_ip_list = []

    for ip_address in ip_keys:
        src = ip_address[0]
        dest = ip_address[1]
        if src not in router_ip_list and dest not in router_ip_list:
            router_ip_list.append(src)
            router_ip_list.append(dest)

    for ip_address in router_ip_list:
        if ip_address == traceroute_src or ip_address == traceroute_dest:
            router_ip_list.remove(ip_address)

    return router_ip_list


def get_protocols(packet_dict):
    """
    Retrieve protocols found in traceroute packet capture.
    :param packet_dict: Dictionary of captured packets
    :return: List of unique dictionaries of protocols utilized
    """
    protocol_list = []
    for ip_tuple, packet in packet_dict.items():
        if packet.protocol not in protocol_list:
            protocol_list.append(packet.protocol)

    return protocol_list


def main():
    if len(sys.argv) < 2:
        raise Exception("No argument provided. Please include an IP traceroute file for analysis.")

    # Read traceroute file
    capture_file = open(sys.argv[1], 'rb')
    packet_capture = dpkt.pcapng.Reader(capture_file)

    parsed_packets = []
    # ip_trace_packets = []

    for timestamp, raw_packet in packet_capture:
        eth = dpkt.ethernet.Ethernet(raw_packet)

        # Check if packet is of type IP.
        # Otherwise, continue.
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            ip_src = socket.inet_ntoa(ip.src)
            ip_dest = socket.inet_ntoa(ip.dst)
            packet_timestamp = datetime.datetime.utcfromtimestamp(timestamp)

            proto_num = ip.p
            proto_name = ip.get_proto(proto_num).__name__

            ip_proto = dict(id=ip.p, protocol=proto_name)
            parsed_packets.append(traceroute_parse.TraceroutePacket(ip_src, ip_dest, packet_timestamp, ip_proto, ip))
        else:
            continue

    traceroute_ip = get_ip(parsed_packets)
    # analyzed_packets = packet_analysis(parsed_packets)
    # routers = get_router_ip(parsed_packets, traceroute_ip[0], traceroute_ip[1])
    # protocols = get_protocols(parsed_packets)

        # # If packet is ICMP, handle as Windows packet
        # if isinstance(ip.data, dpkt.icmp.ICMP):
        #     # AM I LINUX OR IS THIS IS AN EXISTENTIAL CRISIS?? Check for nested UDP within ICMP
        #     if isinstance(ip.data, dpkt.udp.UDP):
        #         pass
        #
        #     # Nope, all good. Just Windows.
        #     else:
        #         windows_packet_analysis()
        #         if ip.ttl >= 1:
        #             icmp = ip.data
        #             ip_packets.append()
        # # If packet is UDP, handle as Linux packet (I AM LINUX BEEP BOOP BOP)
        # elif isinstance(ip.data, dpkt.udp.UDP):
        #     udp = ip.data
        #     port_src = udp.sport
        #     port_dest = udp.dport
        # else:
        #     continue

    # TODO: IP Protocol Analysis - Output
    print("The IP address of the source node: " + traceroute_ip[0])
    print("The IP address of ultimate destination node: " + traceroute_ip[1])

    # router_count = 1
    # print("The IP addresses of the intermediate destination nodes: ")
    # for router_ip in routers:
    #     print("\tRouter {0}: {1}".format(router_count, router_ip))
    #     router_count += 1
    #
    # print("The values in the protocol field of IP headers: ")
    # for protocol in protocols:
    #     print("{0}: {1}".format(protocol['id'], protocol['protocol']))
    #
    # print("\n")
    #
    # print("The number of fragments created from the original datagram is: ")
    # print("The avg RRT between {0} and {1} is: {2}, the s.d. is: {3}".format(source_ip, dest_ip, avg_rtt, sd_rtt))

    print("\n")


if __name__ == '__main__':
    main()