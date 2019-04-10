import socket

from .netcat import Netcat

# TODO this is a bit of a hack. need a base class that we can safely super-call into
class MergePipes(Netcat):
    def __init__(self, readables,
                 verbose=0,
                 log_send=None,
                 log_recv=None,
                 raise_timeout=False,
                 retry=False,
                 log_yield=False):

        self.buf = b''
        self.verbose = verbose
        self.log_send = log_send
        self.log_recv = log_recv
        self.log_yield = log_yield
        self.echo_headers = True
        self.echo_perline = True
        self.echo_sending = True
        self.echo_recving = True
        self.echo_hex = False
        self.echo_send_prefix = '>> '
        self.echo_recv_prefix = '<< '

        self._timeout = None
        self.timed_out = False  # set when an operation times out
        self._raise_timeout = raise_timeout

        if not readables:
            raise ValueError("Need a nonzero number of sockets to read from")
        self.readables = flatten(readables)

    def _recv(self, size):
        goodsocks = select(self.readables, timeout=self._timeout)
        if not goodsocks:
            raise socket.timeout
        goodsock = goodsocks[0]

        if hasattr(goodsock, 'recv'):
            return goodsock.recv(size)
        elif hasattr(goodsock, 'read'):
            return goodsock.read(size)
        else:
            raise ValueError("I don't know how to read from this stream!")

    def _send(self, size):
        raise ValueError("Cannot send to a mergepipes object")

def flatten(readables):
    out = []
    for sock in readables:
        if isinstance(sock, MergePipes):
            out.extend(sock.readables)
        else:
            out.append(sock)
    return out

from .selects import select
