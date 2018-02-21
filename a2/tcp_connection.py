class TCPConnection:
    def __init__(self, id, source_ip, source_port, dest_ip, dest_port):
        """

        :param id:
        :param source_ip:
        :param source_port:
        :param dest_ip:
        :param dest_port:
        """
        self.id = id
        self.source_ip = source_ip
        self.source_port = source_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port