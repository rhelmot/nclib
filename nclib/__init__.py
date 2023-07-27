if bytes is str:
    raise Exception("nclib is python 3 only now :(")

from .netcat import Netcat, ferry, merge
from .select import select
from .server import TCPServer, UDPServer
from .process import Process, GDBProcess
from .errors import NetcatError, NetcatTimeout, NetcatEOF
from . import simplesock

__all__ = ('Netcat', 'ferry', 'merge', 'select', 'TCPServer', 'UDPServer', 'Process', 'GDBProcess', 'simplesock', 'NetcatError', 'NetcatTimeout', 'NetcatEOF')
