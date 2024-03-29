"""
traceroute_analysis.py

Author: AJ Po-Deziel
Created on: 2018-03-12

Perform IP Traceroute Analysis from IP packets gathered via traceroute.
"""

from operator import itemgetter
from traceroute_connection import LinuxTracerouteConnection, WindowsTracerouteConnection
from traceroute_parse import TraceroutePacket
import datetime
import dpkt
import socket
import statistics
import sys


def get_ip(packets):
    first_packet = packets[0]
    source_ip = first_packet.get_ip("src")
    dest_ip = first_packet.get_ip("dest")

    return source_ip, dest_ip


def packet_analysis(packets, origin_ip):
    # Cases to consider

    # 1. src->dest: Establish traceroute connection
    # 2. router->src: Oops, did it again and hit a roadblock (i.e. TTL exceeded)
    # 3. dest->src: 2 sub-cases to look at.
    #   a. Linux: Destination unreachable (counterintuitive, reached dest)
    #   b. Win: Echo reply, reached dest.

    filtered_packets = {}
    global last_offset

    # Analyze traceroute file
    for packet in packets:
        src_ip = packet.get_ip("src")
        dest_ip = packet.get_ip("dest")
        flipped_ip = False

        ip = packet.data

        if dest_ip == origin_ip:
            # Flip src and dest ip around if origin is destination (i.e. reverse ip_tuple)
            key = (dest_ip, src_ip)
            flipped_ip = True
        else:
            key = (src_ip, dest_ip)

        # Case 1: New traceroute
        if not filtered_packets or key not in filtered_packets.keys():
            if isinstance(ip.data, dpkt.icmp.ICMP):
                if isinstance(ip.data.data.data.data, dpkt.udp.UDP):
                    # Linux traceroute packet capture
                    new_traceroute = make_new_traceroute(packet, "UDP")
                else:
                    # Windows traceroute packet capture
                    new_traceroute = make_new_traceroute(packet, "ICMP")
            elif isinstance(ip.data, dpkt.udp.UDP):
                # Linux traceroute packet capture
                new_traceroute = make_new_traceroute(packet, "UDP")
            else:
                continue

            last_offset = ip.off
            filtered_packets[key] = new_traceroute
        # Find the probes, and then map the responses to the respective probes
        else:
            if isinstance(ip.data, dpkt.icmp.ICMP):

                if isinstance(ip.data.data.data.data, dpkt.udp.UDP):
                    # Nested UDP packet in ICMP response
                    # Treat as Linux response packet
                    value = filtered_packets[key]

                    udp = ip.data.data.data.data
                    src_port = udp.sport
                    dest_port = udp.dport

                    if flipped_ip is True:
                        value.rtt_raw.append((src_port, dest_port, packet.timestamp))
                else:
                    # Pure ICMP response
                    # Treat as Windows packet
                    value = filtered_packets[key]

                    if ip.data.type == dpkt.icmp.ICMP_TIMEXCEED:
                        seq_num = ip.icmp.timeexceed.ip.icmp.echo.seq
                    else:
                        seq_num = ip.icmp.echo.seq

                    if flipped_ip is True:
                        value.rtt_raw.append((seq_num, packet.timestamp))
                    else:
                        value.rtt_raw.append((seq_num, packet.timestamp))

                last_offset = ip.off
                filtered_packets[key] = value
            elif isinstance(ip.data, dpkt.udp.UDP):
                # UDP packet encountered, treat as Linux
                if key not in filtered_packets:
                    # ip_tuple does not exist as key in filtered_packets
                    if flipped_ip is True:
                        value = filtered_packets[key]

                        # udp = ip.data.timeexceed.data.icmp.data
                        udp = ip.data
                        src_port = udp.sport
                        dest_port = udp.dport

                        value.rtt_raw.append((src_port, dest_port, packet.timestamp))
                    else:
                        value = filtered_packets[key]

                        # udp = ip.data.timeexceed.data.icmp.data
                        udp = ip.data
                        src_port = udp.sport
                        dest_port = udp.dport

                        value.rtt_raw.append((src_port, dest_port, packet.timestamp))

                    filtered_packets[key] = value
                else:
                    # ip_tuple does exist as key in filtered_packets
                    if flipped_ip is True:
                        value = filtered_packets[key]

                        # udp = ip.data.timeexceed.data.icmp.data
                        udp = ip.data
                        src_port = udp.sport
                        dest_port = udp.dport

                        value.rtt_raw.append((src_port, dest_port, packet.timestamp))
                    else:
                        value = filtered_packets[key]

                        udp = ip.data
                        src_port = udp.sport
                        dest_port = udp.dport

                        value.rtt_raw.append((src_port, dest_port, packet.timestamp))

                    filtered_packets[key] = value
                last_offset = ip.off
            else:
                continue

    # sort filtered_packets by hop count/ttl, then by order of appearance.
    return filtered_packets


def make_new_traceroute(packet, packet_type):
    rtt_raw = []

    start_time = packet.timestamp
    ip = packet.data
    ttl = ip.ttl
    offset = ip.off
    # num_fragments - check out how to determine number of fragments

    if packet_type is "UDP":
        if isinstance(ip.data, dpkt.udp.UDP):
            rtt_raw.append((ip.data.sport, ip.data.dport, packet.timestamp))
            new_dict_item = LinuxTracerouteConnection(start_time, ttl, offset, rtt_raw)
        else:
            rtt_raw.append((ip.data.data.data.data.sport, ip.data.data.data.data.sport, packet.timestamp))
            new_dict_item = LinuxTracerouteConnection(start_time, ttl, offset, rtt_raw)

    if packet_type is "ICMP":
        # Use packet.data.data.seq for tuple creation
        # When accessing TTL Exceed, use ip.icmp.timeexceed.ip.icmp.echo.seq
        if ip.data.type == dpkt.icmp.ICMP_TIMEXCEED:
            rtt_raw.append((ip.icmp.timeexceed.ip.icmp.echo.seq, packet.timestamp))
            new_dict_item = WindowsTracerouteConnection(start_time, ttl, offset, rtt_raw)
        else:
            rtt_raw.append((ip.icmp.echo.seq, packet.timestamp))
            new_dict_item = WindowsTracerouteConnection(start_time, ttl, offset, rtt_raw)

    return new_dict_item


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

    # Ignore origin/source and ultimate destination IPs when adding to router list
    router_ip_list = [y for x, y in ip_keys if y != traceroute_src and y != traceroute_dest]

    return router_ip_list


def get_protocols(packets):
    """
    Retrieve protocols found in traceroute packet capture.
    :param packets: List of captured packets
    :return: List of unique dictionaries of protocols utilized
    """
    protocol_list = []
    for packet in packets:
        if packet.protocol not in protocol_list:
            protocol_list.append(packet.protocol)

    sorted_protocol_list = sorted(protocol_list, key=itemgetter('id'))

    return sorted_protocol_list


def main():
    if len(sys.argv) < 2:
        raise Exception("No argument provided. Please include an IP traceroute file for analysis.")

    # Read traceroute file
    capture_file = open(sys.argv[1], 'rb')
    packet_capture = dpkt.pcapng.Reader(capture_file)

    parsed_packets = []

    for timestamp, raw_packet in packet_capture:
        eth = dpkt.ethernet.Ethernet(raw_packet)

        # Check if packet is of type IP.
        # Otherwise, continue.
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data

            if isinstance(ip.data, dpkt.tcp.TCP):
                continue

            if isinstance(ip.data, dpkt.udp.UDP):
                if isinstance(ip.data.data, dpkt.dns.DNS):
                    continue

            src_addr = socket.inet_ntoa(ip.src)
            dest_addr = socket.inet_ntoa(ip.dst)
            packet_timestamp = datetime.datetime.utcfromtimestamp(timestamp)

            proto_num = ip.p
            proto_name = ip.get_proto(proto_num).__name__

            ip_proto = dict(id=ip.p, protocol=proto_name)
            parsed_packets.append(TraceroutePacket(src_addr, dest_addr, packet_timestamp, ip_proto, ip))
        else:
            continue

    # IP Protocol Analysis methods
    traceroute_ip = get_ip(parsed_packets)
    analyzed_packets = packet_analysis(parsed_packets, traceroute_ip[0])
    routers = get_router_ip(analyzed_packets, traceroute_ip[0], traceroute_ip[1])
    protocols = get_protocols(parsed_packets)


    # TODO: IP Protocol Analysis - Output
    print("The IP address of the source node: {0}".format(traceroute_ip[0]))
    print("The IP address of ultimate destination node: {0}".format(traceroute_ip[1]))

    # Print all router IPs encountered in traceroute packet capture
    router_count = 1
    print("The IP addresses of the intermediate destination nodes: ")
    for router_ip in routers:
        print("\tRouter {0}: {1}".format(router_count, router_ip))
        router_count += 1

    print("")

    # Print all protocols encountered in traceroute packet capture
    print("The values in the protocol field of IP headers: ")
    for protocol in protocols:
        print("\t{0}: {1}".format(protocol['id'], protocol['protocol']))

    print("")

    print("The number of fragments created from the original datagram is: {0}")

    print("")

    print("The offset of the last fragment is: {0}".format(last_offset))

    print("")

    # Print average RTT between origin and intermediate IPs, origin and ultimate destination IPs.
    for ip_key, trace_object in analyzed_packets.items():
        rtt_stats = trace_object.rtt()
        print("The avg RRT between {0} and {1} is: {2:.6f} ms, the s.d. is: {3:.6f} ms".format(ip_key[0], ip_key[1],
                                                                                 rtt_stats[0], rtt_stats[1]))


if __name__ == '__main__':
    main()
