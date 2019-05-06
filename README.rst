nclib
=====

nclib is a python socket library that wants to be your friend.

nclib provides:

- Easy-to-use interfaces for connecting to and listening on TCP and UDP sockets
- The ability to handle any python stream-like object with a single interface
- A better socket class, the Netcat object

  - Convenient receive methods for common socket usage patterns
  - Highly customizable logging
  - Interactive mode, connecting the socket to your stdin/stdout
  - Intelligent detection of socket closes and connection drops
  - Long-running functions cleanly abortable with ctrl-c
  - Lots of aliases in case you forget the right method name

- Mechanisms to launch processes with their in/out streams connected to sockets

  - Launch a process with gdb attached

- TCP and UDP server classes for writing simple python daemons
- A script to easily daemonize command-line programs

If you are familiar with pwntools, nclib provides much of the functionaly that
pwntools' socket wrappers do, but with the bonus feature of not being pwntools.

Installation
------------

.. code-block:: bash

    pip install nclib

Documentation
-------------

https://nclib.readthedocs.io/
