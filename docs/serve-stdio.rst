Daemonizing Command Line Programs
=================================

nclib ships with a utility script called ``serve-stdio`` that can turn any program operating over stdin and stdout into a network service.
This is a task usually accomplished with ``xinetd`` or ``socat``, but for simple one-off applications, this is much easier, and a good demonstration of nclib's capabilities.

Once you've installed nclib, the program ``serve-stdio`` should be installed to your path, and you should be able to run it!::

  $ serve-stdio
  Usage: serve-stdio [options] port command ...
  Options:
    -d       Daemonize, run in background
    -e       Redirect program's stderr to socket
    -E       Hide program's stderr
    -b addr  Bind to a specific address

Example usage::

  $ serve-stdio -d 1234 echo hey
  13282
  $ nc localhost 1234
  hey

By default, the process' stderr stream will be untouched and will probably end
up printed to your terminal.  If you want the socket to see the process'
stderr, you can use the -e flag. If you want the process' stderr to go away
entirely, you can use the -E flag.

How does it work?
It's a very short python script using nclib! The heart of it is just these three lines::

  for client in nclib.TCPServer((bind_addr, port)):
      print('Accepted client %s:%d' % client.peer)
      nclib.Process.launch(command, client, stderr=show_stderr)

Pretty cool!
