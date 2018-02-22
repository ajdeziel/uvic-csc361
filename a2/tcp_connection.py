"""
tcp_connection.py

Class for handling TCP connections in tcp_trace_analysis.py.
"""

class TCPConnection:
    def __init__(self, syn_count, fin_count, start_time, end_time, src_dest_packets, dest_src_packets):
        """
        Class initialization of TCPConnection.

        :param syn_count: SYN flag counter
        :param fin_count: FIN flag counter
        :param start_time: Start time of first packet in connection
        :param end_time: End time of last packet in connection
        :param src_dest_packets: List of packets from source to destination
        :param dest_src_packets: List of packets from destination to source
        """
        self.syn_count = syn_count
        self.fin_count = fin_count
        self.start_time = start_time
        self.end_time = end_time
        self.src_dest_packets = src_dest_packets
        self.dest_src_packets = dest_src_packets

    def tcp_complete(self):
        """
        TCP connection complete status is returned if connection is in one of the following states.
        :return: True / False
        """
        if self.syn_count >= 1 and self.fin_count >= 1:
            return True
        else:
            return False

    def duration(self):
        """
        Get TCP connection's duration.
        :return: end_time of last packet received - start_time of first packet received
        """
        return self.end_time - self.start_time

    def src_dest_packet_count(self):
        """
        Get total of packets sent from source to destination.
        :return: total packets sent from source to destination
        """
        return len(self.src_dest_packets)

    def dest_src_packet_count(self):
        """
        Get total of packets sent from source to destination.
        :return: total packets sent from source to destination
        """
        return len(self.dest_src_packets)

    def total_packet_count(self):
        """
        Get total packets from connection.
        :return: total packets sent between source and destination + total packets sent between destination and source
        """
        return len(self.src_dest_packets) + len(self.dest_src_packets)
