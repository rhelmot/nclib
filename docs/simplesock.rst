Low-level socket abstraction layer
==================================

.. automodule:: nclib.simplesock

Different types of stream-like classes (sockets, files, pipes, ...) have very different interfaces and behaviors under exceptional conditions.
The goal of this "simple socket" module is to provide a unified interface for a variety of stream types.
The Netcat class then uses this interface to provide all the convenient functionality you love.

All Netcat methods should automatically wrap any stream objects you provide with the appropriate wrapper.

.. autoclass:: nclib.simplesock.Simple
  :members:

.. autofunction:: nclib.simplesock.wrap

.. autoclass:: nclib.simplesock.SimpleSocket
.. autoclass:: nclib.simplesock.SimpleFile
.. autoclass:: nclib.simplesock.SimpleDuplex
.. autoclass:: nclib.simplesock.SimpleMerge
