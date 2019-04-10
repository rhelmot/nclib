import getopt
import os
import re
import socket
import sys
import time

from .errors import NetcatError, NetcatTimeout

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

if str is not bytes: # py3
    long = int # pylint: disable=redefined-builtin,invalid-name
    from urllib.parse import urlparse # pylint: disable=no-name-in-module,import-error
else:
    from urlparse import urlparse # pylint: disable=import-error

def _is_ipv6_addr(addr):
    try:
        socket.inet_pton(socket.AF_INET6, addr)
    except socket.error:
        return False
    else:
        return True

class Netcat(object):
    """
    This is the main class you will use to interact with a peer over the
    network! You may instanciate this class to either connect to a server or
    listen for a one-off client.

    One of the following must be passed in order to initialize a Netcat
    object:

    :param connect:     the address/port to connect to
    :param listen:      the address/port to bind to for listening
    :param sock:        a python socket or pipe object to wrap

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
    :param verbose:     Set to True to log data sent/received. The echo_*
                        properties on this object can be tweaked to
                        describe exactly what you want logged.
    :param log_send:    Pass a file-like object open for writing and all
                        data sent over the socket will be written to it.
    :param log_recv:    Pass a file-like object open for writing and all
                        data recieved from the socket will be written to it.
    :param raise_timeout:
                        Whether to raise a NetcatTimeout exception when a
                        timeout is received. The default is to return the
                        empty string and set self.timed_out = True
    :param retry:       Whether to continuously retry establishing a
                        connection if it fails.
    :param log_yield:   Control when logging messages are generated on
                        recv. By default, logging is done when data is
                        received from the socket, and may be buffered.
                        By setting this to true, logging is done when data
                        is yielded to the user, either directly from the
                        socket or from a buffer.

    Any data that is extracted from the target address will override the
    options specified here. For example, a url with the ``http:// scheme``
    will go over tcp and port 80.

    Some properties that may be tweaked to change the logging behavior:

    - nc.echo_headers controls whether to print a header describing each
      network operation before the data (True)
    - nc.echo_perline controls whether the data should be split on newlines
      for logging (True)
    - nc.echo_sending controls whether to log data on send (True)
    - nc.echo_recving controls whether to log data on recv (True)
    - nc.echo_hex controls whether to log data hex-encoded (False)
    - nc.echo_send_prefix controls a prefix to print before each logged
      line of sent data ('>> ')
    - nc.echo_recv_prefix controls a prefix to print before each logged
      line of received data ('<< ')

    Note that these settings ONLY affect the console logging triggered by
    the verbose parameter. They don't do anything to the logging triggered
    by `log_send` and `log_recv`, which are meant to provide pristine
    untouched records of network traffic.

    *Example 1:* Send a greeting to a UDP server listening at 192.168.3.6:8888
    and log the response as hex:

    >>> nc = nclib.Netcat(('192.168.3.6', 8888), udp=True, verbose=True)
    >>> nc.echo_hex = True
    >>> nc.send(b'\\x00\\x0dHello, world!')
    ======== Sending (15) ========
    >> 00 0D 48 65 6C 6C 6F 2C 20 77 6F 72 6C 64 21     |..Hello, world! |
    >>> nc.recv()
    ======== Receiving 4096B or until timeout (default) ========
    << 00 57 68 65 6C 6C 6F 20 66 72 69 65 6E 64 2E 20  |.Whello friend. |
    << 74 69 6D 65 20 69 73 20 73 68 6F 72 74 2E 20 70  |time is short. p|
    << 6C 65 61 73 65 20 64 6F 20 6E 6F 74 20 77 6F 72  |lease do not wor|
    << 72 79 2C 20 79 6F 75 20 77 69 6C 6C 20 66 69 6E  |ry, you will fin|
    << 64 20 79 6F 75 72 20 77 61 79 2E 20 62 75 74 20  |d your way. but |
    << 64 6F 20 68 75 72 72 79 2E                       |do hurry.       |

    *Example 2:* Listen for a local TCP connection on port 1234, allow the user
    to interact with the client. Log the entire interaction to log.txt.

    >>> logfile = open('log.txt', 'wb')
    >>> nc = nclib.Netcat(listen=('localhost', 1234), log_send=logfile, log_recv=logfile)
    >>> nc.interact()
    """
    def __init__(self,
                 connect=None,
                 sock=None,
                 listen=None,
                 server=None,
                 sock_send=None,
                 udp=False,
                 ipv6=False,
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

        self.sock = None
        self._sock_send = sock_send
        self.peer = None

        # case: Netcat(host, port)
        if isinstance(connect, str) and isinstance(listen, int):
            connect = (connect, listen)

        # case: Netcat(sock)
        if isinstance(connect, socket.socket):
            sock = connect
            connect = None

        # deprecated server kwarg
        if server is not None:
            connect = server

        if sock is None and listen is None and connect is None:
            raise ValueError('Not enough arguments, need at least an '
                             'address or a socket or a listening address!')

        ## we support passing connect as the "name" of the socket
        #if sock is not None and (listen is not None or connect is not None):
        #    raise ValueError("connect or listen arguments may not be "
        #            "provided if sock is provided")

        if listen is not None and connect is not None:
            raise ValueError("connect and listen arguments cannot be provided at the same time")

        if sock is None:
            if listen is not None:
                target = listen
                listen = True
            else:
                target = connect
                listen = False

            target, listen, udp, ipv6 = self._parse_target(target, listen, udp, ipv6)
            self._connect(target, listen, udp, ipv6, retry)
        else:
            self.sock = sock
            self.peer = connect

        try:
            self._timeout = self.sock.gettimeout()
        except AttributeError:
            self._timeout = None
        self.timed_out = False  # set when an operation times out
        self._raise_timeout = raise_timeout

    @property
    def sock_send(self):
        if self._sock_send is None:
            return self.sock
        else:
            return self._sock_send

    @sock_send.setter
    def sock_send(self, val):
        self._sock_send = val

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
                    raise ValueError(exc)

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
                    raise ValueError("Unknown scheme: %s" % parsed.scheme)

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

        elif isinstance(target, (int, long)):
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
                self.buf, self.peer = self.sock.recvfrom(1024)
                self.sock.connect(self.peer)
                self._log_recv(self.buf, False)
            if self.verbose:
                self._print_verbose('Connection from %s accepted' % str(self.peer))
        else:
            while True:
                try:
                    self.sock.connect(target)
                except (socket.gaierror, socket.herror) as exc:
                    raise NetcatError('Could not connect to %r: %r' \
                            % (target, exc))
                except socket.error as exc:
                    if retry:
                        time.sleep(0.2)
                    else:
                        raise NetcatError('Could not connect to %r: %r' \
                                % (target, exc))
                else:
                    break
            self.peer = target

    def close(self):
        """
        Close the socket.
        """
        if self._sock_send is not None:
            self._sock_send.close()
        return self.sock.close()

    def shutdown(self, how=socket.SHUT_RDWR):
        """
        Send a shutdown signal for both reading and writing, or whatever
        socket.SHUT_* constant you like.

        Shutdown differs from closing in that it explicitly changes the state of
        the socket resource to closed, whereas closing will only decrement the
        number of peers on this end of the socket, since sockets can be a
        resource shared by multiple peers on a single OS. When the number of
        peers reaches zero, the socket is closed, but not deallocated, so you
        still need to call close. (except that this is python and close is
        automatically called on the deletion of the socket)

        http://stackoverflow.com/questions/409783/socket-shutdown-vs-socket-close
        """
        if self._sock_send is not None:
            self._sock_send.shutdown(how)
        return self.sock.shutdown(how)

    def shutdown_rd(self):
        """
        Send a shutdown signal for reading - you may no longer read from this
        socket.
        """
        if self._sock_send is not None:
            self.sock.close()
        else:
            return self.shutdown(socket.SHUT_RD)

    def shutdown_wr(self):
        """
        Send a shutdown signal for writing - you may no longer write to this
        socket.
        """
        if self._sock_send is not None:
            self._sock_send.close()
        else:
            return self.shutdown(socket.SHUT_WR)

    def fileno(self):
        """
        Return the file descriptor associated with this socket
        """
        if self._sock_send is not None:
            raise UserWarning("Calling fileno when there are in fact two filenos")
        return self.sock.fileno()

    def _print_verbose(self, s):
        assert isinstance(s, str), "s should be str"
        sys.stdout.write(s + '\n')

    def _print_header(self, header):
        if self.verbose and self.echo_headers:
            self._print_verbose(header)

    def _print_recv_header(self, fmt, timeout, *args):
        if self.verbose and self.echo_headers:
            if timeout == 'default':
                timeout = self._timeout
            if timeout is not None:
                timeout_text = ' or until timeout ({0})'.format(timeout)
            else:
                timeout_text = ''

            self._print_verbose(fmt.format(*args, timeout_text=timeout_text))

    def _log_something(self, data, prefix):
        if self.echo_perline:
            if self.echo_hex:
                self._print_hex_lines(data, prefix)
            else:
                self._print_lines(data, prefix)
        else:
            if self.echo_hex:
                if hasattr(data, 'hex'):
                    self._print_verbose(prefix + data.hex())
                else:
                    self._print_verbose(prefix + data.encode('hex'))
            else:
                self._print_verbose(prefix + str(data))

    def _log_recv(self, data, yielding):
        if yielding == self.log_yield:
            if self.verbose and self.echo_recving:
                self._log_something(data, self.echo_recv_prefix)
            if self.log_recv:
                self.log_recv.write(data)

    def _log_send(self, data):
        if self.verbose and self.echo_sending:
            self._log_something(data, self.echo_send_prefix)
        if self.log_send:
            self.log_send.write(data)

    def _print_lines(self, s, prefix):
        for line in s.split(b'\n'):
            self._print_verbose(prefix + str(line))

    @staticmethod
    def _to_spaced_hex(s):
        if isinstance(s, str):
            return ' '.join('%02X' % ord(a) for a in s)
        if isinstance(s, bytes):
            return ' '.join('%02X' % a for a in s)
        raise TypeError('expected str or bytes instance')

    @staticmethod
    def _to_printable_str(s):
        if isinstance(s, str):
            return ''.join(a if ' ' <= a <= '~' else '.' for a in s)
        if isinstance(s, bytes):
            return ''.join(chr(a) if ord(' ') <= a <= ord('~') else '.' for a in s)
        raise TypeError('expected str or bytes instance')

    def _print_hex_lines(self, s, prefix):
        for i in range(0, len(s), 16):
            block = s[i:i+16]
            spaced_hex = self._to_spaced_hex(block)
            printable_str = self._to_printable_str(block)
            self._print_verbose('%s%-47s  |%-16s|' % (prefix, spaced_hex, printable_str))

    def settimeout(self, timeout):
        """
        Set the default timeout in seconds to use for subsequent socket
        operations
        """
        self._timeout = timeout
        self._settimeout(timeout)

    def _send(self, data):
        if hasattr(self.sock_send, 'send'):
            return self.sock_send.send(data)
        elif hasattr(self.sock_send, 'write'):
            return self.sock_send.write(data) # pylint: disable=no-member
        else:
            raise ValueError("I don't know how to write to this stream!")

    def _recv(self, size):
        if hasattr(self.sock, 'recv'):
            return self.sock.recv(size)
        elif hasattr(self.sock, 'read'):
            return self.sock.read(size)    # pylint: disable=no-member
        else:
            raise ValueError("I don't know how to read from this stream!")

    def _recv_predicate(self, predicate, timeout='default', raise_eof=True):
        """
        Receive until predicate returns a positive integer.
        The returned number is the size to return.
        """

        if timeout == 'default':
            timeout = self._timeout

        self.timed_out = False

        start = time.time()
        try:
            while True:
                cut_at = predicate(self.buf)
                if cut_at > 0:
                    break
                if timeout is not None:
                    time_elapsed = time.time() - start
                    if time_elapsed > timeout:
                        raise socket.timeout
                    self._settimeout(timeout - time_elapsed)

                data = self._recv(4096)
                self._log_recv(data, False)
                self.buf += data

                if not data:
                    if raise_eof:
                        raise NetcatError("Connection dropped!")
                    cut_at = len(self.buf)
                    break

        except KeyboardInterrupt:
            self._print_header('\n======== Connection interrupted! ========')
            raise
        except socket.timeout:
            self.timed_out = True
            if self._raise_timeout:
                raise NetcatTimeout()
            return b''
        except socket.error as exc:
            raise NetcatError('Socket error: %r' % exc)

        self._settimeout(self._timeout)

        ret = self.buf[:cut_at]
        self.buf = self.buf[cut_at:]
        self._log_recv(ret, True)
        return ret

    def _settimeout(self, timeout):
        """
        Internal method - catches failures when working with non-timeoutable
        streams, like files
        """
        try:
            self.sock.settimeout(timeout)
        except AttributeError:
            pass

    def gettimeout(self):
        """
        Retrieve the timeout currently associated with the socket
        """
        return self._timeout

    def flush(self):
        # no buffering
        pass

    def recv(self, n=4096, timeout='default'):
        """
        Receive at most n bytes (default 4096) from the socket

        Aliases: read, get
        """

        self._print_recv_header(
            '======== Receiving {0}B{timeout_text} ========', timeout, n)

        return self._recv_predicate(lambda s: min(n, len(s)), timeout)

    def recv_until(self, s, max_size=None, timeout='default'):
        """
        Recieve data from the socket until the given substring is observed.
        Data in the same datagram as the substring, following the substring,
        will not be returned and will be cached for future receives.

        Aliases: read_until, readuntil, recvuntil
        """

        self._print_recv_header(
            '======== Receiving until {0}{timeout_text} ========', timeout, repr(s))

        if max_size is None:
            max_size = 2 ** 62

        def _predicate(buf):
            try:
                return min(buf.index(s) + len(s), max_size)
            except ValueError:
                return 0 if len(buf) < max_size else max_size
        return self._recv_predicate(_predicate, timeout)

    def recv_all(self, timeout='default'):
        """
        Return all data recieved until connection closes.

        Aliases: read_all, readall, recvall
        """

        self._print_recv_header('======== Receiving until close{timeout_text} ========', timeout)

        return self._recv_predicate(lambda s: 0, timeout, raise_eof=False)

    def recv_exactly(self, n, timeout='default'):
        """
        Recieve exactly n bytes

        Aliases: read_exactly, readexactly, recvexactly
        """

        self._print_recv_header(
            '======== Receiving until exactly {0}B{timeout_text} ========', timeout, n)

        return self._recv_predicate(lambda s: n if len(s) >= n else 0, timeout)

    def send(self, s):
        """
        Sends all the given data to the socket.

        Aliases: write, put, sendall, send_all
        """
        self._print_header('======== Sending ({0}) ========'.format(len(s)))

        self._log_send(s)
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
        self._print_header('======== Beginning interactive session ========')

        if hasattr(outsock, 'buffer'):
            outsock = outsock.buffer    # pylint: disable=no-member

        self.timed_out = False

        save_verbose = self.verbose
        self.verbose = 0
        try:
            if self.buf:
                outsock.write(self.buf)
                outsock.flush()
                self.buf = b''

            while True:
                readable_socks = select(self.sock, insock)
                for readable in readable_socks:
                    if readable is insock:
                        data = os.read(insock.fileno(), 4096)
                        self.send(data)
                        if not data:
                            raise NetcatError
                    else:
                        data = self.recv(timeout=None)
                        outsock.write(data)
                        outsock.flush()
                        if not data:
                            raise NetcatError
        except KeyboardInterrupt:
            self.verbose = save_verbose
            self._print_header('\n======== Connection interrupted! ========')
            raise
        except (socket.error, NetcatError):
            self.verbose = save_verbose
            self._print_header('\n======== Connection dropped! ========')
        finally:
            self.verbose = save_verbose

    LINE_ENDING = b'\n'

    def recv_line(self, max_size=None, timeout='default', ending=None):
        """
        Recieve until the next newline , default "\\n". The newline string can
        be changed by changing ``nc.LINE_ENDING``. The newline will be returned
        as part of the string.

        Aliases: recvline, readline, read_line, readln, recvln
        """
        if ending is None:
            ending = self.LINE_ENDING
        return self.recv_until(ending, max_size, timeout)

    def send_line(self, line, ending=None):
        """
        Write the string to the wire, followed by a newline. The newline string
        can be changed by changing ``nc.LINE_ENDING``.

        Aliases: sendline, writeline, write_line, writeln, sendln
        """
        if ending is None:
            ending = self.LINE_ENDING
        return self.send(line + ending)

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

from .selects import select

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
