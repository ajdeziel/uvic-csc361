"""
traceroute_connection.py

Author: AJ Po-Deziel
Created on: 2018-03-12

Data structure to store IP connection data.
"""

import statistics


class LinuxTracerouteConnection():
    def __init__(self, start_time, ttl, offset, sent, recvd):
        self.start_time = start_time
        self.ttl = ttl
        # self.num_fragments = num_fragments
        self.offset = offset
        self.sent = sent
        self.recvd = recvd

    def rtt(self):
        # Linux
        # sent in format [(src_port, dest_port, timestamp)]
        # recvd in format [(src_port, dest_port, timestamp)]
        rtt_list = []
        for packet_sent in self.sent:
            for packet_recvd in self.recvd:
                if packet_sent[0] == packet_recvd[0] and packet_sent[1] == packet_recvd[1]:
                    time_diff = packet_recvd[2] - packet_sent[2]
                    rtt_list.append(time_diff.total_seconds() * 1000)

        return statistics.mean(rtt_list), statistics.stdev(rtt_list)


class WindowsTracerouteConnection():
    def __init__(self, start_time, ttl, offset, sent, recvd):
        self.start_time = start_time
        self.ttl = ttl
        self.offset = offset
        self.sent = sent
        self.recvd = recvd

    def rtt(self):
        # Windows
        # sent in format [(seq_num, timestamp)]
        # recvd in format [(seq_num, timestamp)]
        # REMEMBER: Windows packets will have same sequence numbers, but will be nested in ICMP response. Be prepared to dig.
        rtt_list = []
        for packet_sent in self.sent:
            for packet_recvd in self.recvd:
                if packet_sent[0] == packet_recvd[0]:
                    time_diff = packet_recvd[1] - packet_sent[1]
                    rtt_list.append(time_diff.total_seconds() * 1000)

        return statistics.mean(rtt_list), statistics.stdev(rtt_list)
