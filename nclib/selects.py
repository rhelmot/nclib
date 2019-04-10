import select as _select

def select(*args, **kwargs):
    timeout = kwargs.get('timeout', None)

    if len(args) == 1 and hasattr(args, '__iter__'):
        args = list(args[0])

    socks = flatten(args)

    out = []
    toselect = []
    for sock in socks:
        if type(sock) is Netcat and sock.buf:
            out.append(sock)
        else:
            toselect.append(sock)

    if not toselect:
        return out

    newgood = _select.select(toselect, [], [], 0)[0]

    # I really don't understand the below clause... past me what's up
    if out or newgood or timeout == 0:
        return out + newgood
    #if out or len(newgood) == len(toselect) or timeout == 0:
    #    # the `out or` part is the reason we need this clause
    #    return out + newgood

    toselect = [x for x in toselect if x not in newgood]
    out += newgood

    newgood = _select.select(toselect, [], [], timeout)[0]
    return out + newgood

from .netcat import Netcat
from .merge import flatten
