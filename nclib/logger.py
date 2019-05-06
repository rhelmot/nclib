class Logger:
    """
    The base class for loggers for use with Netcat objects. Each of these
    methods will be called to indicate a given event.
    """
    def connected(self, peer):
        """
        Called with a tuple of the peer to indicate "connection established",
        either as a client or a server
        """

    def sending(self, data):
        """
        Called to indicate that some data has been sent over the wire
        """

    def buffering(self, data):
        """
        Called to indicate that some data has been received and inserted into
        the buffer
        """

    def unbuffering(self, data):
        """
        Called to indicate that some data is being extracted from the buffer
        and returned to the user
        """

    def interrupted(self):
        """
        Called to indicate that a socket operation was interrupted via ctrl-c
        """

    def eofed(self):
        """
        Called to indicate that reading from the socket resulted in an EOF
        condition
        """

    def requesting_send(self, data):
        """
        Called to indicate that the user has asked to send all of some data
        """

    def requesting_recv(self, n, timeout):
        """
        Called to indicate that the user has asked for a receive of at most n
        bytes
        """

    def requesting_recv_until(self, s, max_size, timeout):
        """
        Called to indicate that the user has asked to receive until a given
        string appears
        """

    def requesting_recv_all(self, timeout):
        """
        Called to indicate that the user has asked to receive all data until
        close
        """

    def requesting_recv_exactly(self, n, timeout):
        """
        Called to indicate that the user has asked to receive exactly n bytes
        """

    def interact_starting(self):
        """
        Called to indicate that an interactive session is beginning
        """

    def interact_ending(self):
        """
        Called to indicate that an interactive session is ending
        """

class ManyLogger(Logger):
    """
    A logger which dispatches all events to all its children, which are other
    loggers. You shouldn't have to deal with this much; it's used automatically
    by the Netcat.

    :param children:        A list of loggers to which to dispatch events
    """
    def __init__(self, children):
        self.children = children

    def connected(self, peer):
        for child in self.children:
            child.connected(peer)

    def sending(self, data):
        for child in self.children:
            child.sending(data)

    def buffering(self, data):
        for child in self.children:
            child.buffering(data)

    def unbuffering(self, data):
        for child in self.children:
            child.unbuffering(data)

    def interrupted(self):
        for child in self.children:
            child.interrupted()

    def eofed(self):
        for child in self.children:
            child.eofed()

    def requesting_send(self, data):
        for child in self.children:
            child.requesting_send(data)

    def requesting_recv(self, n, timeout):
        for child in self.children:
            child.requesting_recv(n, timeout)

    def requesting_recv_until(self, s, max_size, timeout):
        for child in self.children:
            child.requesting_recv_until(s, max_size, timeout)

    def requesting_recv_all(self, timeout):
        for child in self.children:
            child.requesting_recv_all(timeout)

    def requesting_recv_exactly(self, n, timeout):
        for child in self.children:
            child.requesting_recv_exactly(n, timeout)

    def interact_starting(self):
        for child in self.children:
            child.interact_starting()

    def interact_ending(self):
        for child in self.children:
            child.interact_ending()

class TeeLogger(Logger):
    """
    A logger which feeds a copy of the input and output streams to a given stream

    :param log_send:    A simplesock object to log all sends to, or None
    :param log_recv:    A simplesock object to log all recvs to, or None
    :param log_yield:   Whether recv logging should happen when data is
                        buffered or returned to the user
    """
    def __init__(self, log_send=None, log_recv=None, log_yield=False):
        self.log_send = log_send
        self.log_recv = log_recv
        self.log_yield = log_yield

    def sending(self, data):
        if self.log_send is not None:
            self.log_send.send(data)

    def buffering(self, data):
        if not self.log_yield and self.log_recv is not None:
            self.log_recv.send(data)

    def unbuffering(self, data):
        if self.log_yield and self.log_recv is not None:
            self.log_recv.send(data)

class StandardLogger(Logger):
    """
    A logger which produces a human-readable log of what's happening

    :param log:             A simplesock object to which the logs should
                            be sent
    :param log_yield:       Whether to log receives when they are recieved
                            and written to the buffer or when they are
                            unbuffered and returned to the user
    :param show_headers:    Whether to show metadata notices about user
                            actions and exceptional conditions
    :param hex_dump:        Whether to encode logged data as a canonical
                            hexdump
    :param split_newlines:  When in non-hex mode, whether logging should
                            treat newlines as record separators
    """
    def __init__(self, log, log_yield=False, show_headers=True,
            hex_dump=False, split_newlines=True,
            send_prefix='>> ', recv_prefix='<< ', no_eol_indicator='\x1b[3m%\x1b[0m'):
        self.log = log
        self.log_yield = log_yield
        self.show_headers = show_headers
        self.hex_dump = hex_dump
        self.split_newlines = split_newlines
        self.send_prefix = send_prefix
        self.recv_prefix = recv_prefix
        self.no_eol_indicator = no_eol_indicator

        self.suppressed = False
        self.counter_send = 0
        self.counter_recv = 0

    def _log(self, s):
        self.log.send(s.encode())

    def _header(self, s):
        if self.show_headers:
            self._log('======= %s =======\n' % s)

    def sending(self, data):
        if self.suppressed:
            return
        self._log_data(data, self.counter_send, self.send_prefix)
        self.counter_send += len(data)

    def _recving(self, data):
        if self.suppressed:
            return
        self._log_data(data, self.counter_recv, self.recv_prefix)
        self.counter_recv += len(data)

    def _log_data(self, data, counter, prefix):
        if not data:
            return

        if self.hex_dump:
            line_progress = counter % 16
            first_line_size = 16 - line_progress
            first_line = data[:first_line_size]
            self._log(prefix + self._hex_line(counter, first_line))

            for i in range(first_line_size, len(data), 16):
                line = data[i:i+16]
                self._log(prefix + self._hex_line(counter + i, line))

        else:
            noeol = False
            if self.split_newlines:
                records = data.split(b'\n')
                if len(records) > 1 and records[-1] == b'':
                    records.pop()
                else:
                    noeol = True
            else:
                records = [data]

            for i, record in enumerate(records):
                sep = (self.no_eol_indicator if noeol and i == len(records) - 1 else '') + '\n'
                self._log(prefix + self._escape(record) + sep)

    @staticmethod
    def _hex_line(counter, line):
        advance = counter % 16
        tail = 16 - advance - len(line)
        lhex = line.hex().upper()
        lhex = '  '*advance + lhex + '  '*tail
        lascii = ' '*advance + ''.join(chr(c) if 0x20 <= c <= 0x7e else '.' for c in line) + ' '*tail

        fargs = (counter,) + tuple(lhex[i:i+2] for i in range(0, 0x20, 2)) + (lascii,)
        return '%06X  %s %s %s %s %s %s %s %s  %s %s %s %s %s %s %s %s  |%s|\n' % fargs

    @staticmethod
    def _escape(bs):
        return ''.join(StandardLogger._escchr(c) for c in bs)

    @staticmethod
    def _escchr(c):
        if c == ord('\\'):
            return '\\\\'
        if c == ord('\n'):
            return '\\n'
        if c == ord('\t'):
            return '\\t'
        if c < 0x20 or c > 0x7e:
            return '\\x%02x' % c
        return chr(c)

    def buffering(self, data):
        if not self.log_yield:
            self._recving(data)

    def unbuffering(self, data):
        if self.log_yield:
            self._recving(data)

    def connected(self, peer):
        self._header("Connected to %s" % str(peer))

    def interrupted(self):
        self._header("Connection interrupted")

    def eofed(self):
        self._header("Received EOF")

    def requesting_send(self, data):
        if self.suppressed:
            return
        self._header("Sending %d byte%s" % (len(data), '' if len(data) == 1 else 's'))

    @staticmethod
    def _timeout_text(timeout):
        if timeout is None:
            return ''
        if timeout == 0:
            return ' (nonblocking)'
        return ' (until %s second%s)' % (timeout, '' if timeout == 1 else 's')

    def requesting_recv(self, n, timeout):
        if self.suppressed:
            return
        self._header("Receiving at most %d byte%s%s" % (n, '' if n == 1 else 's', self._timeout_text(timeout)))

    def requesting_recv_until(self, s, max_size, timeout):
        if self.suppressed:
            return
        if max_size is not None:
            max_size_text = ', max of %d byte%s' % (max_size, '' if max_size == 1 else 's')
        else:
            max_size_text = ''

        self._header("Receiving until %s%s%s" % (repr(s).strip('b'), max_size_text, self._timeout_text(timeout)))

    def requesting_recv_all(self, timeout):
        if self.suppressed:
            return
        self._header("Receiving until close%s" % self._timeout_text(timeout))

    def requesting_recv_exactly(self, n, timeout):
        self._header("Receiving exactly %d byte%s%s" % (n, '' if n == 1 else 's', self._timeout_text(timeout)))

    def interact_starting(self):
        self._header("Beginning interactive session")
        self.suppressed = True

    def interact_ending(self):
        self.suppressed = False
