import getopt
import re
import socket
import sys
import time
from urllib.parse import urlparse
from typing import Optional, Union

from . import simplesock, select, errors, logger

PROTOCAL_RE = re.compile('^[a-z0-9]+://')
KNOWN_SCHEMES = {
    # schema: (udp, ipv6, port); None = unchanged
    'tcp': (False, None, None),
    'tcp4': (False, False, None),
    'tcp6': (False, True, None),
    'udp': (True, None, None),
    'udp4': (True, False, None),
    'udp6': (True, True, None),
    'http': (False, None, 80),
    'https': (False, None, 443),
    'dns': (True, None, 53),
    'ftp': (False, None, 20),
    'ssh': (False, None, 22),
    'smtp': (False, None, 25),
}
BYTESISH = Union[bytes, str]

def encode(b: BYTESISH) -> bytes:
    if type(b) is str:
        return b.encode()
    elif type(b) is bytes:
        return b
    else:
        raise ValueError("Value must be str or bytes (preferably bytes)")

def _is_ipv6_addr(addr):
    try:
        socket.inet_pton(socket.AF_INET6, addr)
    except socket.error:
        return False
    else:
        return True

class Netcat:
    """
    This is the main class you will use to interact with a peer over the
    network! You may instanciate this class to either connect to a server,
    listen for a one-off client, or wrap an existing sock/pipe/whatever.

    One of the following must be passed in order to initialize a Netcat
    object:

    :param connect:     the address/port to connect to
    :param listen:      the address/port to bind to for listening
    :param sock:        a python socket, pipe, file, etc to wrap

    For ``connect`` and ``listen``, they accept basically any argument format
    known to mankind. If you find an input format you think would be useful but
    isn't accepted, let me know :P

    Additionally, the following options modify the behavior of the object:

    :param sock_send:   If this is specified, this Netcat object will act
                        as a multiplexer/demultiplexer, using the "normal"
                        channel for receiving and this channel for sending.
                        This should be specified as a python socket or pipe
                        object.

                        .. warning:: Using ``sock_send`` will cause issues if
                                     you pass this object into a context which
                                     expects to be able to use its
                                     ``.fileno()``.

    :param udp:         Set to True to use udp connections when using the
                        connect or listen parameters
    :param ipv6:        Force using ipv6 when using the connect or listen
                        parameters
    :param retry:       The number of times to retry establishing a connection
                        after a short (200ms) sleep if it fails.
    :param raise_timeout:
                        Whether to raise a `NetcatTimeout` exception when a
                        timeout is received. The default is to return any
                        buffered data and set ``self.timed_out`` = True
    :param raise_eof:   Whether to raise a `NetcatEOF` exception when EOF
                        is encountered. The default is to return any buffered
                        data and set ``self.eof = True``
    :param loggers:     A list of `Logger` objects to consume socket events
                        for logging.

    The following options can be used to configure default loggers:

    :param log_send:    Pass a file-like object open for writing and all
                        data sent over the socket will be written to it.
    :param log_recv:    Pass a file-like object open for writing and all
                        data recieved from the socket will be written to it.
    :param verbose:     Set to True to cause a log of socket activity to be
                        written to stderr.
    :param echo_headers:
                        Controls whether stderr logging should print headers
                        describing network operations and exceptional
                        conditions.
    :param echo_perline:
                        Controls whether stderr logging should treat newlines
                        as record separators.
    :param echo_hex:    Controls whether stderr logging should produce a
                        hexdump.
    :param echo_send_prefix:
                        A prefix to print to stderr before each logged line of
                        sent data.
    :param echo_recv_prefix:
                        A prefix to print to stderr before each logged line of
                        received data.
    :param log_yield:   Control when logging messages are generated on
                        recv. By default, logging is done when data is
                        received from the socket, and may be buffered.
                        By setting this to True, logging is done when data
                        is yielded to the user, either directly from the
                        socket or from a buffer. This affects both stderr
                        and tee logging.

    Any data that is extracted from the target address will override the
    options specified here. For example, a url with the ``http://`` scheme
    will go over tcp and port 80.

    You may use this constructor as a context manager, i.e.
    ``with nclib.Netcat(...) as nc:``, and the socket will be automatically
    closed when control exits the with-block.

    *Example 1:* Send a greeting to a UDP server listening at 192.168.3.6:8888
    and wait for a response. Log the conversation to stderr as hex.

    >>> nc = nclib.Netcat(('192.168.3.6', 8888),
    ...        udp=True, verbose=True, echo_hex=True)
    ======= Connected to ('localhost', 8888) =======
    >>> nc.send(b'\\x00\\x0dHello, world!')
    ======= Sending 15 bytes =======
    >> 000000  00 0D 48 65 6C 6C 6F 2C  20 77 6F 72 6C 64 21     |..Hello, world! |
    >>> response = nc.recv()
    ======= Receiving at most 4096 bytes =======
    << 000000  00 57 68 65 6C 6C 6F 20  66 72 69 65 6E 64 2E 20  |.Whello friend. |
    << 000010  74 69 6D 65 20 69 73 20  73 68 6F 72 74 2E 20 70  |time is short. p|
    << 000020  6C 65 61 73 65 20 74 6F  20 6E 6F 74 20 77 6F 72  |lease to not wor|
    << 000030  72 79 2C 20 79 6F 75 20  77 69 6C 6C 20 66 69 6E  |ry, you will fin|
    << 000040  64 20 79 6F 75 72 20 77  61 79 2E 20 62 75 74 20  |d your way. but |
    << 000050  64 6F 20 68 75 72 72 79  2E                       |do hurry.       |
    >>> nc.send(b'\\x00\\x08oh no D:')
    ======= Sending 10 bytes =======
    >> 00000F                                                00  |               .|
    >> 000010  08 6F 68 20 6E 6F 20 44  3A                       |.oh no D:       |

    *Example 2:* Listen for a local TCP connection on port 1234, allow the user
    to interact with the client. Log the entire interaction to log.txt.

    >>> logfile = open('log.txt', 'wb')
    >>> nc = nclib.Netcat(listen=('localhost', 1234), log_send=logfile, log_recv=logfile)
    >>> nc.interact()
    """

    #
    # Initializer functions
    #

    def __init__(self, connect=None, sock=None, listen=None,
                 sock_send=None, server=None,
                 udp=False, ipv6=False,
                 raise_timeout=False, raise_eof=False,
                 retry=0,
                 loggers=None,

                 # canned options
                 verbose=0,
                 log_send=None, log_recv=None, log_yield=False,
                 echo_headers=True, echo_perline=True, echo_hex=False,
                 echo_send_prefix='>> ', echo_recv_prefix='<< ',
            ):

        # handle canned logger options
        if loggers is None:
            loggers = []
        if verbose:
            l = logger.StandardLogger(
                    _xwrap(sys.stderr),
                    log_yield=log_yield,
                    show_headers=echo_headers,
                    hex_dump=echo_hex,
                    split_newlines=echo_perline,
                    send_prefix=echo_send_prefix,
                    recv_prefix=echo_recv_prefix)
            loggers.append(l)
        if log_send is not None or log_recv is not None:
            l = logger.TeeLogger(
                    log_send=_xwrap(log_send) if log_send is not None else None,
                    log_recv=_xwrap(log_recv) if log_recv is not None else None,
                    log_yield=log_yield)
            loggers.append(l)

        # set properties
        self.logger = logger.ManyLogger(loggers)
        self.buf = b''
        self.sock = None
        self.peer = None

        self.timed_out = False  # set when an operation times out
        self.eof = False
        self._raise_timeout = raise_timeout
        self._raise_eof = raise_eof

        # handle several "convenient" args-passing cases
        # case: Netcat(host, port)
        if isinstance(connect, str) and isinstance(sock, int):
            connect = (connect, sock)
            sock = None

        # case: Netcat(sock)
        if hasattr(connect, 'read') or hasattr(connect, 'recv'):
            sock = connect
            connect = None

        # server= as alias for connect=
        if server is not None:
            connect = server

        # sanity checks
        if sock is None and listen is None and connect is None:
            raise ValueError('Not enough arguments, need at least an '
                             'address or a socket or a listening address!')

        if listen is not None and connect is not None:
            raise ValueError("connect and listen arguments cannot be provided at the same time")

        # three cases: 1) already have a sock 2) need to do a connect 3) need to do a listen
        if sock is None:
            if listen is not None:
                target = listen
                listen = True
            else:
                target = connect
                listen = False

            target, listen, udp, ipv6 = self._parse_target(target, listen, udp, ipv6)
            self._connect(target, listen, udp, ipv6, int(retry))
        else:
            self.sock = sock
            self.peer = connect

        # extract the timeout from the sock before we wrap it in the simplesock
        try:
            self._timeout = self.sock.gettimeout()
        except AttributeError:
            self._timeout = None

        # do simplesock wrapping and take sock_send into account
        self.sock = _xwrap(self.sock)
        if sock_send is not None:
            self.sock = simplesock.SimpleDuplex(self.sock, _xwrap(sock_send))

    @staticmethod
    def _parse_target(target, listen, udp, ipv6):
        """
        Takes the basic version of the user args and extract as much data as
        possible from target. Returns a tuple that is its arguments but
        sanitized.
        """
        if isinstance(target, str):
            if target.startswith('nc '):
                out_host = None
                out_port = None

                try:
                    opts, pieces = getopt.getopt(target.split()[1:], 'u46lp:',
                                                 [])
                except getopt.GetoptError as exc:
                    raise ValueError(exc) from exc

                for opt, arg in opts:
                    if opt == '-u':
                        udp = True
                    elif opt == '-4':
                        ipv6 = False
                    elif opt == '-6':
                        ipv6 = True
                    elif opt == '-l':
                        listen = True
                    elif opt == '-p':
                        out_port = int(arg)
                    else:
                        assert False, "unhandled option"

                if not pieces:
                    pass
                elif len(pieces) == 1:
                    if listen and pieces[0].isdigit():
                        out_port = int(pieces[0])
                    else:
                        out_host = pieces[0]
                elif len(pieces) == 2 and pieces[1].isdigit():
                    out_host = pieces[0]
                    out_port = int(pieces[1])
                else:
                    raise ValueError("Bad cmdline: %s" % target)

                if out_host is None:
                    if listen:
                        out_host = '::' if ipv6 else '0.0.0.0'
                    else:
                        raise ValueError("Missing address: %s" % target)
                if out_port is None:
                    raise ValueError("Missing port: %s" % target)

                if _is_ipv6_addr(out_host):
                    ipv6 = True

                return (out_host, out_port), listen, udp, ipv6

            elif PROTOCAL_RE.match(target) is not None:
                parsed = urlparse(target)
                port = None

                try:
                    scheme_udp, scheme_ipv6, scheme_port = KNOWN_SCHEMES[parsed.scheme]
                except KeyError:
                    raise ValueError("Unknown scheme: %s" % parsed.scheme) from None

                if scheme_udp is not None:
                    udp = scheme_udp
                if scheme_ipv6 is not None:
                    ipv6 = scheme_ipv6
                if scheme_port is not None:
                    port = scheme_port

                if parsed.netloc.startswith('['):
                    addr, extra = parsed.netloc[1:].split(']', 1)
                    if extra.startswith(':'):
                        port = int(extra[1:])
                else:
                    if ':' in parsed.netloc:
                        addr, port = parsed.netloc.split(':', 1)
                        port = int(port)
                    else:
                        addr = parsed.netloc

                if addr is None or port is None:
                    raise ValueError("Can't parse addr/port from %s" % target)

                if _is_ipv6_addr(addr):
                    ipv6 = True

                return (addr, port), listen, udp, ipv6

            else:
                if target.startswith('['):
                    addr, extra = target[1:].split(']', 1)
                    if extra.startswith(':'):
                        port = int(extra[1:])
                    else:
                        port = None
                else:
                    if ':' in target:
                        addr, port = target.split(':', 1)
                        port = int(port)
                    else:
                        addr = target
                        port = None

                if port is None:
                    raise ValueError("No port given: %s" % target)

                if _is_ipv6_addr(addr):
                    ipv6 = True

                return (addr, port), listen, udp, ipv6

        elif isinstance(target, int):
            if listen:
                out_port = target
            else:
                raise ValueError("Can't deal with number as connection address")

            return ('::' if ipv6 else '0.0.0.0', out_port), listen, udp, ipv6

        elif isinstance(target, tuple):
            if len(target) >= 1 and isinstance(target[0], str) and _is_ipv6_addr(target[0]):
                ipv6 = True
            return target, listen, udp, ipv6

        else:
            raise ValueError("Can't parse target: %r" % target)

    def _connect(self, target, listen, udp, ipv6, retry):
        """
        Takes target/listen/udp/ipv6 and sets self.sock and self.peer
        """
        ty = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
        fam = socket.AF_INET6 if ipv6 else socket.AF_INET
        self.sock = socket.socket(fam, ty)
        if listen:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(target)
            if not udp:
                self.sock.listen(1)
                conn, addr = self.sock.accept()
                self.sock.close()
                self.sock = conn
                self.peer = addr
            else:
                self.buf, self.peer = self.sock.recvfrom(4096)
                self.sock.connect(self.peer)
                self.logger.buffering(self.buf)
        else:
            while retry >= 0:
                try:
                    self.sock.connect(target)
                except (socket.gaierror, socket.herror) as exc:
                    raise errors.NetcatError('Could not connect to %r' \
                            % (target,)) from exc
                except socket.error as exc:
                    if retry:
                        time.sleep(0.2)
                        retry -= 1
                    else:
                        raise errors.NetcatError('Could not connect to %r:' \
                                % (target,)) from exc
                else:
                    break
            self.peer = target
        self.logger.connected(self.peer)

    def __enter__(self):
        return self

    def __exit__(self, ty, val, tb):
        self.close()

    def add_logger(self, l):
        """
        Add the given logger to the list of current loggers
        """
        self.logger.children.append(l)

    def remove_logger(self, l):
        """
        Remove the given logger from the list of current loggers
        """
        self.logger.children.remove(l)

    #
    # Socket metadata functionality
    #

    def close(self):
        """
        Close the socket.
        """
        return self.sock.close()

    # inconsistent between sockets and files. support both
    @property
    def closed(self) -> bool:
        """
        Whether the socket has been closed by the user (not the peer).
        """
        return self.sock.closed

    @property
    def _closed(self) -> bool:
        return self.closed

    def shutdown(self, how=socket.SHUT_RDWR):
        """
        Send a shutdown signal for one or both of reading and writing. Valid
        arguments are ``socket.SHUT_RDWR``, ``socket.SHUT_RD``, and
        ``socket.SHUT_WR``.

        Shutdown differs from closing in that it explicitly changes the state of
        the socket resource to closed, whereas closing will only decrement the
        number of peers on this end of the socket, since sockets can be a
        resource shared by multiple peers on a single OS. When the number of
        peers reaches zero, the socket is closed, but not deallocated, so you
        still need to call close. (except that this is python and close is
        automatically called on the deletion of the socket)

        http://stackoverflow.com/questions/409783/socket-shutdown-vs-socket-close
        """
        return self.sock.shutdown(how)

    def shutdown_rd(self):
        """
        Send a shutdown signal for reading - you may no longer read from this
        socket.
        """
        return self.shutdown(socket.SHUT_RD)

    def shutdown_wr(self):
        """
        Send a shutdown signal for writing - you may no longer write to this
        socket.
        """
        return self.shutdown(socket.SHUT_WR)

    def fileno(self) -> int:
        """
        Return the file descriptor associated with this socket
        """
        return self.sock.fileno()

    def settimeout(self, timeout):
        """
        Set the default timeout in seconds to use for subsequent socket
        operations. Set to None to wait forever, or 0 to be effectively
        nonblocking.
        """
        self._timeout = timeout

    def gettimeout(self) -> Optional[float]:
        """
        Retrieve the timeout currently associated with the socket
        """
        return self._timeout

    def flush(self):
        # no output buffering
        pass

    def _prep_select(self):
        return self.sock._prep_select()

    #
    # Core socket data functionality
    #

    def _send(self, data: bytes) -> int:
        ret = self.sock.send(data)
        self.logger.sending(data[:ret])
        return ret

    def _recv(self, size: int, timeout: Optional[float]=None) -> bytes:
        """
        one-shot recv with timeout.
        all timeouts are expressed via raising errors.NetcatTimeout
        we wait until data is ready and then recv.
        TODO: this is not thread safe...
        """
        if timeout is not None:
            r, _, _ = select.select([self.sock], timeout=timeout)  # pylint: disable=no-member
            if not r:
                raise errors.NetcatTimeout()
        try:
            data = self.sock.recv(size)
        except ConnectionResetError:
            data = b''
        self.logger.buffering(data)
        return data

    def _recv_predicate(self, predicate, timeout: Optional[float], raise_eof: Optional[bool]=None) -> bytes:
        """
        this is the core function which ties together all the nclib features
        it will buffer data and call the predicate function on the buffer
        until it returns a positive integer: the amount to unbuffer.
        """
        if timeout is None:
            deadline = None
        else:
            deadline = time.time() + timeout
        self.timed_out = False

        if raise_eof is None:
            raise_eof = self._raise_eof

        try:
            first_shot = True
            while True:
                # step 1: check if the needed data is buffered.
                # if so set cut_at and break out
                cut_at = predicate(self.buf)
                if cut_at > 0:
                    break

                # step 2: calculate timeout for this read.
                # if it's elapsed, raise error
                if deadline is not None:
                    timeout = deadline - time.time()
                    if timeout < 0:
                        if first_shot:
                            timeout = 0
                        else:
                            raise errors.NetcatTimeout()
                first_shot = False

                # step 3: receive a chunk with timeout and buffer it
                data = self._recv(4096, timeout)
                self.buf += data

                # step 4: handle EOF. raise_eof=False should mean return the
                # rest of the buffer regardless of predicate
                if not data:
                    self.eof = True
                    self.logger.eofed()
                    if raise_eof:
                        raise errors.NetcatEOF("Connection dropped!")
                    cut_at = len(self.buf)
                    break
                self.eof = False

        # handle interrupt
        except KeyboardInterrupt:
            self.logger.interrupted()
            raise

        # handle timeout. needs to be done this way since recv may raise
        # timeout too
        except errors.NetcatTimeout:
            self.timed_out = True
            if self._raise_timeout:
                raise
            cut_at = len(self.buf)

        # handle arbitrary socket errors. should this be moved inward?
        except socket.error as e:
            raise errors.NetcatError('Socket error') from e

        # unbuffer whatever we need to return
        ret = self.buf[:cut_at]
        self.buf = self.buf[cut_at:]
        self.logger.unbuffering(ret)
        return ret

    #
    # Public socket data functions
    #

    def _fixup_timeout(self, timeout='default') -> Optional[float]:
        if timeout == 'default':
            return self._timeout
        return timeout

    def recv(self, n: int=4096, timeout='default') -> bytes:
        """
        Receive at most n bytes (default 4096) from the socket

        Aliases: read, get
        """

        timeout = self._fixup_timeout(timeout)
        self.logger.requesting_recv(n, timeout)
        return self._recv_predicate(lambda s: min(n, len(s)), timeout)

    def recv_until(self, s: BYTESISH, max_size: Optional[int]=None, timeout='default') -> bytes:
        """
        Recieve data from the socket until the given substring is observed.
        Data in the same datagram as the substring, following the substring,
        will not be returned and will be cached for future receives.

        Aliases: read_until, readuntil, recvuntil
        """
        s = encode(s)
        timeout = self._fixup_timeout(timeout)
        self.logger.requesting_recv_until(s, max_size, timeout)

        if max_size is None:
            max_size = 2 ** 62

        def _predicate(buf):
            try:
                return min(buf.index(s) + len(s), max_size)
            except ValueError:
                return 0 if len(buf) < max_size else max_size
        return self._recv_predicate(_predicate, timeout)

    def recv_all(self, timeout='default') -> bytes:
        """
        Return all data recieved until connection closes or the timeout
        elapses.

        Aliases: read_all, readall, recvall
        """

        timeout = self._fixup_timeout(timeout)
        self.logger.requesting_recv_all(timeout)
        return self._recv_predicate(lambda s: 0, timeout, raise_eof=False)

    def recv_exactly(self, n: int, timeout='default') -> bytes:
        """
        Recieve exactly n bytes

        Aliases: read_exactly, readexactly, recvexactly, recv_exact,
        read_exact, readexact, recvexact
        """

        timeout = self._fixup_timeout(timeout)
        self.logger.requesting_recv_exactly(n, timeout)
        return self._recv_predicate(lambda s: n if len(s) >= n else 0, timeout)

    def send(self, s: BYTESISH) -> int:
        """
        Sends all the given data to the socket.

        Aliases: write, put, sendall, send_all
        """
        s = encode(s)
        self.logger.requesting_send(s)

        out = len(s)
        while s:
            s = s[self._send(s):]
        return out

    def interact(self, insock=sys.stdin, outsock=sys.stdout):
        """
        Connects the socket to the terminal for user interaction.
        Alternate input and output files may be specified.

        This method cannot be used with a timeout.

        Aliases: interactive, interaction
        """
        self.logger.interact_starting()
        other = Netcat(simplesock.SimpleDuplex(_xwrap(insock), _xwrap(outsock)))
        ferry(self, other, suppress_timeout=True, suppress_raise_eof=True)
        self.logger.interact_ending()

    #
    # Public socket data functionality
    # (implemented with other public socket data functions)
    #

    LINE_ENDING = b'\n'

    def recv_line(self, max_size: Optional[int]=None, timeout='default', ending: Optional[BYTESISH]=None):
        """
        Recieve until the next newline , default "\\n". The newline string can
        be changed by changing ``nc.LINE_ENDING``. The newline will be returned
        as part of the string.

        Aliases: recvline, readline, read_line, readln, recvln
        """
        if ending is None:
            ending = self.LINE_ENDING
        return self.recv_until(ending, max_size, timeout)

    def send_line(self, line: BYTESISH, ending: Optional[BYTESISH]=None):
        """
        Write the string to the wire, followed by a newline. The newline string
        can be changed by specifying the ``ending`` param or changing
        ``nc.LINE_ENDING``.

        Aliases: sendline, writeline, write_line, writeln, sendln
        """
        if ending is None:
            ending = self.LINE_ENDING
        ending = encode(ending)
        line = encode(line)
        return self.send(line + ending)

    #
    # Aliases :D
    #

    read = recv
    get = recv

    write = send
    put = send
    sendall = send
    send_all = send

    read_until = recv_until
    readuntil = recv_until
    recvuntil = recv_until

    read_all = recv_all
    readall = recv_all
    recvall = recv_all

    read_exactly = recv_exactly
    readexactly = recv_exactly
    recvexactly = recv_exactly
    recv_exact = recv_exactly
    read_exact = recv_exactly
    readexact = recv_exactly
    recvexact = recv_exactly

    interactive = interact
    ineraction = interact

    recvline = recv_line
    readline = recv_line
    read_line = recv_line
    readln = recv_line
    recvln = recv_line

    sendline = send_line
    writeline = send_line
    write_line = send_line
    writeln = send_line
    sendln = send_line

def merge(children, **kwargs):
    """
    Return a Netcat object whose receives will be the merged stream of all the
    given children sockets.

    :param children:    A list of socks of any kind to receive from
    :param kwargs:      Any additional keyword arguments will be passed on to
                        the Netcat constructor. Notably, you might want to
                        specify `sock_send`, since by default you will not
                        be able to send data to a merged socket.
    """
    nice_children = [_xwrap(child) for child in children]
    return Netcat(simplesock.SimpleMerge(nice_children), **kwargs)

def _xwrap(sock):
    """
    like simplesock.wrap but will also *unwrap* Netcat objects into their
    constituent sockets. Be warned that this will discard buffers.
    """
    return sock.sock if isinstance(sock, Netcat) else simplesock.wrap(sock)


def ferry(left, right, ferry_left=True, ferry_right=True,
        suppress_timeout=True, suppress_raise_eof=False):
    """
    Establish a linkage between two socks, automatically copying any data
    that becomes available between the two.

    :param left:                A netcat sock
    :param right:               Another netcat sock
    :param ferry_left:          Whether to copy data leftward, i.e. from the
                                right sock to the left sock
    :param ferry_right:         Whether to copy data rightward, i.e. from the
                                left sock to the right sock
    :param suppress_timeout:    Whether to automatically set the socks'
                                timeout property to None and then reset it at
                                the end
    :param suppress_raise_eof:  Whether to automatically set the socks'
                                raise_eof property to None and then reset it at
                                the end
    """

    left_timeout = left._timeout
    left_raise_eof = left._raise_eof
    right_timeout = right._timeout
    right_raise_eof = right._raise_eof

    selectable = []
    if ferry_left:
        selectable.append(right)
    if ferry_right:
        selectable.append(left)
    if not selectable:
        return

    try:
        if suppress_timeout:
            left._timeout = None
            right._timeout = None
        if suppress_raise_eof:
            left._raise_eof = False
            right._raise_eof = False

        while True:
            r, _, _ = select.select(selectable)  # pylint: disable=no-member
            for readable in r:
                data = readable.recv()
                if not data:
                    raise errors.NetcatEOF()

                if readable is left:
                    right.send(data)
                else:
                    left.send(data)
    except (KeyboardInterrupt, errors.NetcatEOF):
        pass
    finally:
        if suppress_timeout:
            left._timeout = left_timeout
            right._timeout = right_timeout
        if suppress_raise_eof:
            left._raise_eof = left_raise_eof
            right._raise_eof = right_raise_eof


# congrats, you've found the secret in-progress command-line python netcat! it barely works.
#def add_arg(arg, options, args):
#    if arg in ('v',):
#        options['verbose'] += 1
#    elif arg in ('l',):
#        options['listen'] = True
#    elif arg in ('k',):
#        options['listenmore'] = True
#    else:
#        raise NetcatError('Bad argument: %s' % arg)
#
#def usage(verbose=False):
#    print """Usage: %s [-vlk] hostname port""" % sys.argv[0]
#    if verbose:
#        print """More help coming soon :)"""
#
#def main(*args_list):
#    args = iter(args_list)
#    args.next()
#    hostname = None
#    port = None
#    options = {'verbose': False, 'listen': False, 'listenmore': False}
#    for arg in args:
#        if arg.startswith('--'):
#            add_arg(arg, options, args)
#        elif arg.startswith('-'):
#            for argchar in arg[1:]:
#                add_arg(argchar, options, args)
#        else:
#            if arg.isdigit():
#                if port is not None:
#                    if hostname is not None:
#                        usage()
#                        raise NetcatError('Already specified hostname and port: %s' % arg)
#                    hostname = port # on the off chance the host is totally numeric :P
#                port = int(arg)
#            else:
#                if hostname is not None:
#                    usage()
#                    raise NetcatError('Already specified hostname: %s' % arg)
#                hostname = arg
#    if port is None:
#        usage()
#        raise NetcatError('No port specified!')
#    if options['listen']:
#        hostname = '0.0.0.0' if hostname is None else hostname
#        while True:
#            Netcat(listen=(hostname, port), verbose=options['verbose']).interact()
#            if not options['listenmore']:
#                break
#    else:
#        if hostname is None:
#            usage()
#            raise NetcatError('No hostname specified!')
#        Netcat(server=(hostname, port), verbose=options['verbose']).interact()
#
#
#if __name__ == '__main__':
#    main(*sys.argv)
