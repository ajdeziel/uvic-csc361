"""
tcp_connection.py

Class for handling TCP connections in tcp_trace_analysis.py.
"""

class TCPConnection:
    def __init__(self, syn_count, fin_count, start_time, end_time, sent_packets, recvd_packets):
        """
        Class initialization of TCPConnection.

        :param syn_count: SYN flag counter
        :param fin_count: FIN flag counter
        :param start_time: Start time of first packet in connection
        :param end_time: End time of last packet in connection
        :param sent_packets: List of packets from source to destination
        :param recvd_packets: List of packets from destination to source
        """
        self.syn_count = syn_count
        self.fin_count = fin_count
        self.start_time = start_time
        self.end_time = end_time
        self.sent_packets = sent_packets
        self.recvd_packets = recvd_packets

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

    def packet_count(self):
        """
        Get total of packets sent from source to destination.
        :return: total packets sent from source to destination
        """
        return len(self.packets)

    def bytes_sent(self):
        """
        Get total number of bytes sent from source to destination.
        :return: total bytes of packets sent from source to destination
        """
        total_size = 0
        for packet in self.sent_packets:
            total_size += len(packet)
        return total_size

    def bytes_received(self):
        """
        Get total number of bytes sent from destination to source.
        :return: total bytes of packets sent from destination to source
        """
        total_size = 0
        for packet in self.recvd_packets:
            total_size += len(packet)
        return total_size
