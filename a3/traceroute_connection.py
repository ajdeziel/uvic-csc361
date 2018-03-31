"""
traceroute_connection.py

Author: AJ Po-Deziel
Created on: 2018-03-12

Data structure to store IP connection data.
"""

import statistics


class LinuxTracerouteConnection():
    def __init__(self, start_time, ttl, offset, rtt_raw):
        self.start_time = start_time
        self.ttl = ttl
        # self.num_fragments = num_fragments
        self.offset = offset
        self.rtt_raw = rtt_raw
        # self.recvd = recvd

    def rtt(self):
        # Linux
        # sent in format [(src_port, dest_port, timestamp)]
        # recvd in format [(src_port, dest_port, timestamp)]
        rtt_list = []
        for packet_1 in self.rtt_raw:
            for packet_2 in self.rtt_raw:
                if packet_1[0] == packet_2[0] and packet_1[1] == packet_2[1]:
                    if packet_1[2] != packet_2[2]:
                        time_diff = packet_2[2] - packet_1[2]
                        rtt_list.append(time_diff.total_seconds() * 1000)

        final_rtt = [x for x in rtt_list if x >= 0]

        return statistics.mean(final_rtt), statistics.stdev(final_rtt)


class WindowsTracerouteConnection():
    def __init__(self, start_time, ttl, offset, rtt_raw):
        self.start_time = start_time
        self.ttl = ttl
        self.offset = offset
        self.rtt = rtt_raw
        # self.recvd = recvd

    def rtt(self):
        # Windows
        # sent in format [(seq_num, timestamp)]
        # recvd in format [(seq_num, timestamp)]
        # REMEMBER: Windows packets will have same sequence numbers, but will be nested in ICMP response. Be prepared to dig.
        rtt_list = []
        for packet_1 in self.rtt_raw:
            for packet_2 in self.rtt_raw:
                if packet_1[0] == packet_2[0]:
                    if packet_1[1] != packet_2[1]:
                        time_diff = packet_2[1] - packet_1[1]
                        rtt_list.append(time_diff.total_seconds() * 1000)

        final_rtt = [x for x in rtt_list if x >= 0]

        return statistics.mean(final_rtt), statistics.stdev(final_rtt)
