Logging Facilities
==================

.. automodule:: nclib.logger

Netcat objects can be instrumented by providing a Logger object to its constructor.
The job of a Logger is to receive events provided by the Netcat (for example, "we are sending data" or "we got an EOF") and do something with them.

.. autoclass:: nclib.logger.Logger
  :members:

.. autoclass:: nclib.logger.StandardLogger
.. autoclass:: nclib.logger.TeeLogger
.. autoclass:: nclib.logger.ManyLogger
