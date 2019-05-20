import subprocess
import os
import random

from .netcat import Netcat

class Process(Netcat):
    """
    A mechanism for launching a local process and interacting with it
    programatically.  This class is a subclass of the basic `Netcat` object so
    you may use any method from that class to interact with the process you've
    launched!

    :param program:     The program to launch. Can be either a list of strings,
                        in which case those strings will become the program
                        argv, or a single string, in which case the shell will
                        be used to launch the program.
    :param stderr:      How the program's stderr stream should behave. True
                        (default) will redirect stderr to the output socket,
                        unifying it with stdout. False will redirect it to
                        /dev/null. None will not touch it, causing it to appear
                        on your terminal.
    :param cwd:         The working directory to execute the program in
    :param env:         The environment to execute the program in, as a
                        dictionary

    Any additional keyword arguments will be passed to the constructor of
    Netcat.

    WARNING: If you provide a string and not a list as the description for the
    program to launch, then the pid we know about will be associated with the
    shell that launches the program, not the program itself.

    *Example:* Launch the `cat` process and send it a greeting. Print out its
    response. Close the socket and the process exits with status 0.

    >>> from nclib import Process
    >>> cat = Process('cat')
    >>> cat.send('Hello world!')
    >>> print(cat.recv())
    b'Hello world!'
    >>> cat.close()
    >>> print(cat.poll())
    0
    """
    def __init__(self, program,
            stderr=True,
            cwd=None,
            env=None,
            **kwargs):
        self._subprocess = self.launch(program, stderr=stderr, cwd=cwd, env=env)
        self.pid = self._subprocess.pid

        super().__init__(
                sock=self._subprocess.stdout,
                sock_send=self._subprocess.stdin,
                server='local program %s' % program, **kwargs)

    def poll(self):
        """
        Return the exit code of the proces, or None if it has not exited.
        """
        return self._subprocess.poll()

    def wait(self):
        """
        Wait for the process to exit and return its exit code.
        """
        return self._subprocess.wait()

    def send_signal(self, sig):
        """
        Send the signal `sig` to the process.
        """
        return self._subprocess.send_signal(sig)

    def kill(self):
        """
        Terminate the process.
        """
        return self._subprocess.kill()

    @staticmethod
    def launch(program, sock=None, stderr=True, cwd=None, env=None):
        """
        A static method for launching a process.
        Same rules from the Process constructor apply.

        :param sock:    The socket to use for stdin/stdout. If None, will be a new set of pipes.
        """

        if stderr is True:
            stderr = subprocess.STDOUT
        elif stderr is False:
            stderr = subprocess.DEVNULL

        if sock is None:
            sock = subprocess.PIPE

        return subprocess.Popen(program,
                shell=type(program) not in (list, tuple),
                stdin=sock, stdout=sock, stderr=stderr,
                cwd=cwd, env=env,
                close_fds=True)


class GDBProcess(Process):
    """
    Like nclib.Process, but also launches gdb (in a new $TERMINAL, by default gnome-terminal)
    to debug the process.
    """
    def __init__(self, program, gdbscript=None, **kwargs):
        """
        :param program:     The program to launch. Can be either a list of strings, in which case
                            those strings will become the program argv, or a single string, in which
                            case the shell will be used to launch the program.
        :param stderr:      How the program's stderr stream should behave. True (default) will
                            redirect stderr to the output socket, unifying it with stdout. False will
                            redirect it to /dev/null. None will not touch it, causing it to appear
                            on your terminal.
        :param cwd:         The working directory to execute the program in
        :param env:         The environment to execute the program in, as a dictionary
        :param protocol:    The socket protocol to use. 'tcp' by default, can also be 'udp'
        :param gdbscript:   The filename of a script for gdb to execute automatically on startup

        Any additional keyword arguments will be passed to the constructor of Netcat.
        """
        super(GDBProcess, self).__init__(program, **kwargs)

        progbase = (program.split() if type(program) not in (list, tuple) else program)[0]
        # TODO: this should be refactored so it's the other way around
        # we should be fromatting stuff into bytestrings since that's what goes into the syscalls
        if bytes is not str and type(progbase) is bytes:
            progbase = progbase.decode()
        gdbcmd = 'gdb %s -ex "set sysroot" -ex "target remote tcp::%d"' % (progbase, self._subprocess._gdbport) # pylint: disable=no-member
        if gdbscript is not None:
            gdbcmd += " -x '%s'" % (gdbscript.replace("'", "'\"'\"'"))

        nul = open(os.devnull, 'r+b')
        t = os.environ.get("TERMINAL", "gnome-terminal").split()
        self.term = subprocess.Popen(t + ['-e', gdbcmd],
                close_fds=True,
                stdin=nul, stdout=nul, stderr=nul)

        self.recv_until(b'pid = ')
        self.pid = int(self.recvline())
        self.recvline()
        self.recvline()

    @classmethod
    def launch(cls, program, *args, **kwargs):
        gdbport = random.randint(32768, 60999) # default /proc/sys/net/ipv4/ip_local_port_range on my machine
        gdbcmd = ['gdbserver', 'localhost:%d' % gdbport]
        if type(program) not in (list, tuple):
            if bytes is not str and type(program) is bytes:
                program = program.decode()
            program = '%s %s' % (' '.join(gdbcmd), program)
        else:
            program = gdbcmd + program

        p = super(GDBProcess, cls).launch(program, *args, **kwargs)
        p._gdbport = gdbport
        return p
