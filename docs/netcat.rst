Basic socket interfaces
=======================

.. automodule:: nclib.netcat

.. autoclass:: nclib.netcat.Netcat
   :members: __init__, send, send_line, recv, recv_until, recv_all, recv_exactly, interact, close, closed, shutdown, shutdown_rd, shutdown_wr, fileno, settimeout, gettimeout

.. autofunction:: nclib.select.select
.. autofunction:: nclib.netcat.ferry


.. automodule:: nclib.errors

.. autoclass:: nclib.errors.NetcatError
.. autoclass:: nclib.errors.NetcatEOF
.. autoclass:: nclib.errors.NetcatTimeout
