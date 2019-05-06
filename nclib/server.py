import socket

from . import Netcat

class TCPServer:
    """
    A simple TCP server model. Iterating over it will yield client sockets as
    Netcat objects.

    :param bindto:          The address to bind to, a tuple (host, port)
    :param kernel_backlog:  The argument to listen()

    Any additional keyword arguments will be passed to the constructor of the
    Netcat object that is constructed for each client.

    Here is a simple echo server example:

    >>> from nclib import TCPServer
    >>> server = TCPServer(('0.0.0.0', 1337))
    >>> for client in server:
    ...     client.send(client.recv()) # or submit to a thread pool for async handling...

    """
    def __init__(self, bindto, kernel_backlog=5, **kwargs):
        self.addr = bindto
        self.kwargs = kwargs

        self.sock = socket.socket(type=socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(bindto)
        self.sock.listen(kernel_backlog)

    def __iter__(self):
        while True:
            client, addr = self.sock.accept()
            yield Netcat(sock=client, server=addr, **self.kwargs)

    def close(self):
        """
        Tear down this server and release its resources
        """
        return self.sock.close()


class UDPServer:
    """
    A simple UDP server model. Iterating over it will yield of tuples of
    datagrams and peer addresses. To respond, use the respond method, which
    takes the response and the peer address.

    :param bindto:      The address to bind to, a tuple (host, port)
    :param dgram_size:  The size of the datagram to receive. This is
                        important! If you send a message longer than the
                        receiver's receiving size, the rest of the message
                        will be silently lost! Default is 4096.

    Here is a simple echo server example:

    >>> from nclib import UDPServer
    >>> server = UDPServer(('0.0.0.0', 1337))
    >>> for message, peer in server:
    ...     server.respond(message, peer) # or submit to a thread pool for async handling...

    """
    def __init__(self, bindto, dgram_size=4096):
        self.addr = bindto
        self.dgram_size = dgram_size
        self.sock = socket.socket(type=socket.SOCK_DGRAM)

    def __iter__(self):
        while True:
            packet, peer = self.sock.recvfrom(self.dgram_size)
            yield packet, peer

    def respond(self, packet, peer, flags=0):
        """
        Send a message back to a peer.

        :param packet:      The data to send
        :param peer:        The address to send to, as a tuple (host, port)
        :param flags:       Any sending flags you want to use for some reason
        """
        self.sock.sendto(packet, flags, peer)

    def close(self):
        """
        Tear down this server and release its resources
        """
        return self.sock.close()
