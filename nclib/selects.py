import select as _select

def select(*args, **kwargs):
    timeout = kwargs.get('timeout', None)

    if len(args) == 1 and hasattr(args, '__iter__'):
        args = list(args[0])

    out = []
    toselect = []
    for sock in args:
        if type(sock) is Netcat and sock.buf:
            out.append(sock)
        else:
            toselect.append(sock)

    if not toselect:
        return out

    newgood = _select.select(toselect, [], [], 0)[0]

    if out or len(newgood) == len(toselect) or timeout == 0:
        # the `out or` part is the reason we need this clause
        return out + newgood

    toselect = [x for x in toselect if x not in newgood]
    out += newgood

    newgood = _select.select(toselect, [], [], timeout)[0]
    return out + newgood

from .netcat import Netcat
