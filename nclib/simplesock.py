import socket
import io
import logging

from .select import select
from .errors import NetcatError

class Simple:
    """
    The base class for implementing a simple, unified interface for socket-like
    objects. Instances of this type should act like a simple unbuffered
    blocking socket.

    :ivar can_send: Whether this stream supports send operations
    :ivar can_recv: Whether this stream supports recv operations
    """
    def __init__(self):
        self.can_send = False
        self.can_recv = False

    def recv(self, size):
        """
        Receive at most `size` bytes, blocking until some data is available.
        Returns an empty bytestring as an EOF condition.
        """
        raise NotImplementedError

    def send(self, data):
        """
        Send as much of the given data as possible, returning the number of
        bytes sent.
        """
        raise NotImplementedError

    def close(self):
        """
        Close the stream.
        """
        raise NotImplementedError

    @property
    def closed(self):
        """
        Whether the stream has been closed.
        """
        raise NotImplementedError

    def fileno(self):
        """
        The file descriptor associated with the stream. Should raise
        `NetcatError` if there is not a single file descriptor to return.
        """
        raise NotImplementedError

    def shutdown(self, how):
        """
        Indicate somehow that there will be no more reading/writing/both to
        this stream. Takes the ``socket.SHUT_*`` constants.
        """
        raise NotImplementedError

    def _prep_select(self):
        """
        Return three tuples of all the raw python file objects that should be
        selected over in order to determine if this stream is
        readable/writable/in an exceptional condition.
        """
        raise NotImplementedError

def wrap(sock):
    """
    A helper function to automatically pick the correct wrapper class for a
    sock-like object.
    """
    if isinstance(sock, Simple):
        return sock
    if isinstance(sock, socket.socket):
        return SimpleSocket(sock)
    if isinstance(sock, io.IOBase):
        return SimpleFile(sock)
    raise ValueError("idk how to work with a %r. check your work or report a bug?" % type(sock))

class SimpleSocket(Simple):
    """
    A wrapper for sockets.

    :param sock:    A python ``socket.socket`` object.
    """
    def __init__(self, sock):
        super().__init__()
        self.sock = sock  # a socket.socket object
        self.can_recv = True
        self.can_send = True

        # disable timeout and enable blocking. this is a simple socket after all.
        sock.settimeout(None)
        sock.setblocking(True)

    def recv(self, size):
        return self.sock.recv(size)

    def send(self, data):
        return self.sock.send(data)

    def close(self):
        return self.sock.close()

    @property
    def closed(self):
        return self.sock._closed

    def fileno(self):
        return self.sock.fileno()

    def shutdown(self, how):
        try:
            return self.sock.shutdown(how)
        except OSError:
            # e.g. udp sockets may do this
            pass

    def _prep_select(self):
        return ((self.sock,) if self.can_recv else ()), ((self.sock,) if self.can_send else ()), (self.sock,)

class SimpleFile(Simple):
    """
    A wrapper for files from the python ``io`` module, including ``sys.stdin``,
    subprocess pipes, etc. If the file has an encoding, it will be discarded.

    :param fp:      An ``io.IOBase`` object
    """
    def __init__(self, fp):
        super().__init__()
        self.please_decode = None
        # a common case is to pass Nclib(log_send=open(file)).
        # this will fail because when we unwrap the object its outer layers are garbage collected
        # which closes the file.
        self._no_garbage_collection_thx = fp

        try: # check if we have a TextIOWrapper
            buf = fp.buffer
            self.please_decode = fp.encoding
            fp = buf
        except AttributeError:
            pass

        try: # check if we have a BufferedReader
            fp = fp.raw
        except AttributeError:
            pass

        self.file = fp  # an io.IOBase object
        self.can_recv = fp.mode.startswith('r')
        self.can_send = fp.mode.startswith('w') or fp.mode.startswith('a') or '+' in fp.mode

    def recv(self, size):
        if not self.can_recv:
            raise Exception("Unsupported operation")
        return self.file.read(size)

    def send(self, data):
        if not self.can_send:
            raise Exception("Unsupported operation")
        return self.file.write(data)

    def close(self):
        return self.file.close()

    @property
    def closed(self):
        return self.file.closed

    def fileno(self):
        return self.file.fileno()

    def shutdown(self, how):
        if how == socket.SHUT_RDWR:
            self.close()
        elif how == socket.SHUT_RD:
            if not self.can_send:
                self.close()
        elif how == socket.SHUT_WR:
            if not self.can_recv:
                self.close()
        else:
            raise ValueError("invalid shutdown `how`", how)

    def _prep_select(self):
        return ((self.file,) if self.can_recv else ()), ((self.file,) if self.can_send else ()), (self.file,)


class SimpleDuplex(Simple):
    """
    A wrapper which splits recv and send operations across two different
    streams.

    :param Simple child_recv:  The stream to use for recving
    :param Simple child_send: The stream to use for sending

    If either of these parameters are None, that operation will be disabled
    and generate exceptions.
    """

    def __init__(self, child_recv=None, child_send=None):
        super().__init__()
        self.child_recv = child_recv
        self.child_send = child_send

        self.can_recv = self.child_recv is not None
        self.can_send = self.child_send is not None

        if self.can_recv and not self.child_recv.can_recv:
            raise NetcatError("Reading sock cannot be used for recving")
        if self.can_send and not self.child_send.can_send:
            raise NetcatError("Sending sock cannot be used for sending")

    def recv(self, size):
        if not self.can_recv:
            raise NetcatError("Unsupported operation")
        return self.child_recv.recv(size)

    def send(self, data):
        if not self.can_send:
            raise NetcatError("Unsupported operation")
        return self.child_send.send(data)

    def close(self):
        if self.can_recv:
            self.child_recv.close()
        if self.can_send:
            self.child_send.close()

    @property
    def closed(self):
        if self.can_recv:
            return self.child_recv.closed
        if self.can_send:
            return self.child_send.closed
        return True

    def fileno(self):
        if self.can_recv:
            if self.can_send:
                raise NetcatError("Socket has multiple filenos")
            return self.child_recv.fileno()
        if self.can_send:
            return self.child_send.fileno()
        raise NetcatError("Socket has no filenos")

    def shutdown(self, how):
        # should these filter the how value so recv never sees a send shutdown etc?
        if self.can_recv:
            self.child_recv.shutdown(how)
        if self.can_send:
            self.child_send.shutdown(how)

    def _prep_select(self):
        rfd = ((), (), ()) if self.child_recv is None else self.child_recv._prep_select()
        wfd = ((), (), ()) if self.child_send is None else self.child_send._prep_select()

        return (rfd[0] if self.can_recv else ()), (wfd[1] if self.can_send else ()), rfd[2] + wfd[2]

class SimpleMerge(Simple):
    """
    A stream that merges the output of many readable streams into one.

    :param children:    A list of streams from which to read
    :type children:     list of Simple
    """
    def __init__(self, children):
        super().__init__()
        self.can_send = False
        self.can_recv = True
        self.children = children

        if any(not child.can_recv for child in children):
            raise Exception("Not all children are applicable for receiving")

    def recv(self, size):
        goodsocks, _, _ = select(self.children)
        if not goodsocks:
            raise Exception("What happened???")

        goodsock = goodsocks[0]
        return goodsock.recv(size)

    def send(self, data):
        raise Exception("Cannot send to a merged socket")

    def close(self):
        for child in self.children:
            child.close()

    @property
    def closed(self):
        # TODO: consistency check?
        return any(child.closed for child in self.children)

    def fileno(self):
        raise Exception("Socket has multiple filenos")

    def shutdown(self, how):
        for child in self.children:
            child.shutdown(how)

    def _prep_select(self):
        stuff = sum((child._prep_select()[0] for child in self.children), ())
        return stuff, (), stuff

class SimpleNetcat(Simple):
    """
    A wrapper for a Netcat object! Why? Just in case you want to do
    Netcat-level instrumentation [logging] at a finer granularity than the
    top-level.

    :param sock:    A Netcat object.
    """
    def __init__(self, nc):
        super().__init__()
        self.nc = nc
        self.can_recv = nc.sock.can_recv
        self.can_send = nc.sock.can_send

        nc.settimeout(None)

    def recv(self, size):
        return self.nc.recv(size)

    def send(self, data):
        return self.nc.send(data)

    def close(self):
        return self.nc.close()

    @property
    def closed(self):
        return self.nc.closed

    def fileno(self):
        return self.nc.fileno()

    def shutdown(self, how):
        return self.nc.shutdown(how)

    def _prep_select(self):
        return self.nc._prep_select()

class SimpleLogger(Simple):
    """
    A socket-like interface for dumping data to a python logging endpoint.

    :param logger:      The dotted name for the endpoint for the logs to go to
    :param level:       The string or numeric severity level for the logging
                        messages
    :param encoding:    simplesock objects are fed bytestrings. Loggers consume
                        unicode strings. How should we translate?
    """
    def __init__(self, logger='nclib.logs', level='INFO', encoding=None):
        super().__init__()
        self.logger = logging.getLogger(logger)
        self.level = logging._checkLevel(level)
        self.encoding = encoding
        self._closed = False

        self.can_recv = False
        self.can_send = True

    def recv(self, size):
        raise NetcatError("Can't recv from a logger object")

    def send(self, data):
        if self._closed:
            raise NetcatError("I'm closed dumbass!")

        if self.encoding is None:
            data = data.decode()
        else:
            data = data.decode(self.encoding)
        self.logger.log(self.level, data)

    def close(self):
        self._closed = True

    @property
    def closed(self):
        return self._closed

    def fileno(self):
        raise NetcatError("Can't make a fileno for you")

    def shutdown(self, how):
        return None

    def _prep_select(self):
        raise NetcatError("Can't be selected")
