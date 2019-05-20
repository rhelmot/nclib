# pylint: disable=wildcard-import
if bytes is str:
    raise Exception("nclib is python 3 only now :(")

from .netcat import Netcat, ferry, merge
from .select import select
from .server import TCPServer, UDPServer
from .process import Process, GDBProcess
from .errors import *
from . import simplesock
