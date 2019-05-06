import select as _select

# hey!!! did you know that you can have nested loops in list/dict/generator comprehensions????
# GUESS WHAT WE'RE DOING HERE
def select(select_read, select_write=(), select_exc=(), timeout=None):
    """
    A select function which works for any netcat or simplesock object.
    This function is a drop-in replacement for python's ``select.select``.

    The main advantage is that sockets with multiple backing file descriptors
    are handled cleanly.
    """
    allsocks = set(sock for sockset in (select_read, select_write, select_exc) for sock in sockset)
    sock_mapping = {sock: sock._prep_select() for sock in allsocks}

    reverse_read = {base: sock for sock, (baselist, _, _) in sock_mapping.items() for base in baselist}
    reverse_write = {base: sock for sock, (_, baselist, _) in sock_mapping.items() for base in baselist}
    reverse_exc = {base: sock for sock, (_, _, baselist) in sock_mapping.items() for base in baselist}

    base_read = list(set(base for sock in select_read for base in sock_mapping[sock][0]))
    base_write = list(set(base for sock in select_write for base in sock_mapping[sock][1]))
    base_exc = list(set(base for sock in select_exc for base in sock_mapping[sock][2]))

    # if any socks in the *original* read have anything buffered, we should treat it as if select
    # returns immediately. however we need to check if any other socks have data buffered in the
    # *kernel*.
    preselected = set(sock for sock in select_read if getattr(sock, 'buf', ()))
    if preselected:
        timeout = 0

    sel_base_read, sel_base_write, sel_base_exc = _select.select(base_read, base_write, base_exc, timeout)

    sel_read = tuple(set(reverse_read[base] for base in sel_base_read) | preselected)
    sel_write = tuple(set(reverse_write[base] for base in sel_base_write))
    sel_exc = tuple(set(reverse_exc[base] for base in sel_base_exc))
    return sel_read, sel_write, sel_exc
