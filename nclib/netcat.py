from __future__ import print_function
import sys, select as _select, os, socket, string, time

from .errors import NetcatError, NetcatTimeout

class Netcat(object):
    """
    This is the main class you will use to interact with a peer over the
    network! You may instanciate this class to either connect to a server or
    listen for a one-off client.

    One of the following must be passed in order to initialize a Netcat
    object:

    :param sock:        a python socket object to wrap
    :param server:      a tuple (host, port) to connect to
    :param listen:      a tuple (host, port) to bind to for listening

    Additionally, the following options modify the behavior of the object:

    :param udp:         Set to True to use udp connections when using the
                        server or listen methods
    :param verbose:     Set to True to log data sent/received. The echo_*
                        properties on this object can be tweaked to
                        describe exactly what you want logged.
    :param log_send:    Pass a file-like object open for writing and all
                        data sent over the socket will be written to it.
    :param log_send:    Pass a file-like object open for writing and all
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
    >>> nc.send('\\x00\\x0dHello, world!')
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
            server=None,
            sock=None,
            listen=None,
            udp=False,
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
        self.echo_send_prefix = b'>> '
        self.echo_recv_prefix = b'<< '

        if sock is None:
            ty = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
            self.sock = socket.socket(type=ty)
            if server is not None:
                while True:
                    try:
                        self.sock.connect(server)
                    except socket.error:
                        if retry:
                            time.sleep(0.2)
                        else:
                            raise
                    else:
                        break
                self.peer = server
            elif listen is not None:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.bind(listen)
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
                if verbose:
                    print('Connection from %s accepted' % str(self.peer))
            else:
                raise ValueError('Not enough arguments, need at least a '
                        'server or a socket or a listening address!')
        else:
            self.sock = sock
            self.peer = server

        try:
            self._timeout = self.sock.gettimeout()
        except AttributeError:
            self._timeout = None
        self.timed_out = False  # set when an operation times out
        self._raise_timeout = raise_timeout

    def _head_buf(self, index=None):
        if index is None:
            out = self.buf
            self.buf = ''
            return out
        else:
            out = self.buf[:index]
            self.buf = self.buf[index:]
            return out

    def close(self):
        """
        Close the socket.
        """
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

    def fileno(self):
        """
        Return the file descriptor associated with this socket
        """
        return self.sock.fileno()

    def _log_something(self, data, prefix):
        if self.echo_perline:
            if self.echo_hex:
                self._print_hex_lines(data, prefix)
            else:
                self._print_lines(data, prefix)
        else:
            if self.echo_hex:
                sys.stdout.write(data.encode('hex'))
            else:
                sys.stdout.write(data)
            sys.stdout.flush()

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

    @staticmethod
    def _print_lines(s, prefix):
        for line in s.split('\n'):
            print(prefix + line)

    @staticmethod
    def _print_hex_lines(s, prefix):
        for i in xrange(0, len(s), 16):
            sl = s[i:i+16]
            line = prefix + ' '.join('%02X' % ord(a) for a in sl)
            if i + 16 >= len(s):
                line += '   '*(16 - len(sl))

            line += '  |'
            for sc in sl:
                if sc == ' ' or (sc in string.printable and sc not in string.whitespace):
                    line += sc
                else:
                    line += '.'
            line += ' '*(16 - len(sl))
            line += '|'
            print(line)

    def settimeout(self, timeout):
        """
        Set the default timeout in seconds to use for subsequent socket
        operations
        """
        self._timeout = timeout
        self._settimeout(timeout)

    def _send(self, data):
        if hasattr(self.sock, 'send'):
            return self.sock.send(data)
        elif hasattr(self.sock, 'write'):
            return self.sock.write(data) # pylint: disable=no-member
        else:
            raise ValueError("I don't know how to write to this stream!")

    def _recv(self, n):
        if hasattr(self.sock, 'recv'):
            return self.sock.recv(n)
        elif hasattr(self.sock, 'read'):
            return self.sock.read(n)    # pylint: disable=no-member
        else:
            raise ValueError("I don't know how to read from this stream!")

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

    def recv(self, n=4096, timeout='default'):
        """
        Receive at most n bytes (default 4096) from the socket

        Aliases: read, get
        """
        self.timed_out = False

        if self.verbose and self.echo_headers:
            if timeout:
                print('======== Receiving {0}B or until timeout ({1}) ========'.format(n, timeout))
            else:
                print('======== Receiving {0}B ========'.format(n))

        ret = b''
        if self.buf:
            ret = self.buf[:n]
            self.buf = self.buf[n:]
            self._log_recv(ret, True)
            return ret

        try:
            if timeout != 'default':
                self._settimeout(timeout)

            a = self._recv(n - len(self.buf))
            if a == b'':
                raise NetcatError("Connection dropped!")
            self._log_recv(a, False)

            self.buf += a
            ret = self.buf
            self.buf = b''
        except socket.timeout:
            self.timed_out = True
            if self._raise_timeout:
                raise NetcatTimeout()
        except socket.error:
            raise NetcatError('Socket error!')

        self._settimeout(self._timeout)

        if not timeout and ret == b'':
            raise NetcatError("Connection dropped!")

        self._log_recv(ret, True)
        return ret

    def recv_until(self, s, max_size=None, timeout='default'):
        """
        Recieve data from the socket until the given substring is observed.
        Data in the same datagram as the substring, following the substring,
        will not be returned and will be cached for future receives.

        Aliases: read_until, readuntil, recvuntil
        """
        self.timed_out = False
        if timeout == 'default':
            timeout = self._timeout

        if self.verbose and self.echo_headers:
            if timeout:
                print('======== Receiving until {0} or timeout ({1}) ========'
                        .format(repr(s), timeout))
            else:
                print('======== Receiving until {0} ========'
                        .format(repr(s)))

        start = time.time()
        try:
            while s not in self.buf \
                    and (max_size is None or len(self.buf) < max_size):
                if timeout is not None:
                    dt = time.time()-start
                    if dt > timeout:
                        self.timed_out = True
                        break
                    self._settimeout(timeout-dt)

                a = self._recv(4096)
                if a == b'':
                    raise NetcatError("Connection dropped!")
                self._log_recv(a, False)

                self.buf += a
        except socket.timeout:
            self.timed_out = True
            if self._raise_timeout:
                raise NetcatTimeout()

        self._settimeout(self._timeout)

        cut_at = self.buf.index(s)+len(s)
        if max_size is not None:
            cut_at = min(cut_at, max_size)

        ret = self._head_buf(cut_at if not self.timed_out else None)
        self._log_recv(ret, True)
        return ret

    def recv_all(self, timeout='default'):
        """
        Return all data recieved until connection closes.

        Aliases: read_all, readall, recvall
        """
        self.timed_out = False
        if timeout == 'default':
            timeout = self._timeout

        if self.verbose and self.echo_headers:
            if timeout:
                print('======== Receiving until close or timeout ({}) ========'
                        .format(timeout))
            else:
                print('======== Receiving until close ========')

        start = time.time()
        try:
            while True:
                if timeout is not None:
                    dt = time.time()-start
                    if dt > timeout:
                        self.timed_out = True
                        break
                    self._settimeout(timeout-dt)

                a = self._recv(4096)
                if not a: break
                self.buf += a
                self._log_recv(a, False)

        except KeyboardInterrupt:
            if self.verbose and self.echo_headers:
                print('\n======== Connection interrupted! ========')
        except socket.timeout:
            self.timed_out = True
            if self._raise_timeout:
                raise NetcatTimeout()
        except (socket.error, NetcatError):
            if self.verbose and self.echo_headers:
                print('\n======== Connection dropped! ========')

        self._settimeout(self._timeout)
        ret = self.buf
        self.buf = b''
        self._log_recv(ret, True)
        return ret

    def recv_exactly(self, n, timeout='default'):
        """
        Recieve exactly n bytes

        Aliases: read_exactly, readexactly, recvexactly
        """
        self.timed_out = False
        if timeout == 'default':
            timeout = self._timeout

        if self.verbose and self.echo_headers:
            if timeout:
                print('======== Receiving until exactly {0}B or timeout({1})  ========'
                        .format(n, timeout))
            else:
                print('======== Receiving until exactly {0}B  ========'
                        .format(n))

        start = time.time()
        try:
            while len(self.buf) < n:
                if timeout is not None:
                    dt = time.time()-start
                    if dt > timeout:
                        self.timed_out = True
                        break
                    self._settimeout(timeout-dt)

                a = self._recv(n - len(self.buf))
                if len(a) == 0:
                    raise NetcatError("Connection closed before {0} bytes received!"
                            .format(n))
                self.buf += a
                self._log_recv(a, False)
        except KeyboardInterrupt:
            if self.verbose and self.echo_headers:
                print('\n======== Connection interrupted! ========')
        except socket.timeout:
            self.timed_out = True
            if self._raise_timeout:
                raise NetcatTimeout()
        except socket.error:
            raise NetcatError("Socket error!")

        out = self.buf[:n]
        self.buf = self.buf[n:]
        self._log_recv(a, True)
        return out

    def send(self, s):
        """
        Sends all the given data to the socket.

        Aliases: write, put, sendall, send_all
        """
        if self.verbose and self.echo_headers:
            print('======== Sending ({0}) ========'.format(len(s)))

        self._log_send(s)

        while s:
            s = s[self._send(s):]

    def interact(self, insock=sys.stdin, outsock=sys.stdout):
        """
        Connects the socket to the terminal for user interaction.
        Alternate input and output files may be specified.

        This method cannot be used with a timeout.

        Aliases: interactive, interaction
        """
        if self.verbose and self.echo_headers:
            print('======== Beginning interactive session ========')

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
            dropped = False
            while not dropped:
                r, _, _ = _select.select([self.sock, insock], [], [])
                for s in r:
                    if s == self.sock:
                        a = self.recv(timeout=None)
                        if a == b'':
                            dropped = True
                        else:
                            outsock.write(a)
                            outsock.flush()
                    else:
                        b = os.read(insock.fileno(), 4096)
                        self.send(b)
            raise NetcatError
        except KeyboardInterrupt:
            if save_verbose and self.echo_headers:
                print('\n======== Connection interrupted! ========')
        except (socket.error, NetcatError):
            if save_verbose and self.echo_headers:
                print('\n======== Connection dropped! ========')
        finally:
            self.verbose = save_verbose

    LINE_ENDING = b'\n'

    def recv_line(self, max_size=None, timeout=None, ending=None):
        """
        Recieve until the next newline , default "\\n". The newline string can
        be changed by changing ``nc.LINE_ENDING``. The newline will be returned
        as part of the string.

        Aliases: recvline, readline, read_line, readln, recvln
        """
        if ending is None: ending = self.LINE_ENDING
        return self.recv_until(ending, max_size, timeout)

    def send_line(self, line, ending=None):
        """
        Write the string to the wire, followed by a newline. The newline string
        can be changed by changing ``nc.LINE_ENDING``.

        Aliases: sendline, writeline, write_line, writeln, sendln
        """
        if ending is None: ending = self.LINE_ENDING
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
