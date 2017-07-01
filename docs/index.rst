nclib
=====

nclib is a python socket library that wants to be your friend.

nclib provides:

- Easy-to-use interfaces for connecting to and listening on TCP and UDP sockets
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

Source code is available at https://github.com/rhelmot/nclib.

If you are familiar with pwntools, nclib provides much of the functionaly that
pwntools' socket wrappers do, but with the bonus feature of not being pwntools.

To install nclib, run ``pip install nclib``.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   netcat
   server
   process
   serve-stdio


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
