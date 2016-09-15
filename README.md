nclib
=====

nclib is netcat as a python library, or at least a couple of common things
netcat can do.

nclib provides:
- Easy-to-use interfaces for connecting to and listening on TCP and UDP sockets
- recv_until, receiving until a given substring comes over the wire
- Highly customizable logging, including logging in hex encoding
- Interactive mode, connecting the socket to your stdin/stdout
- Intelligent detection of socket closes and connection drops
- Long-running functions cleanly abortable with ctrl-c
- Lots of aliases in case you forget the right method name
- A script (serve-stdio) to easily daemonize command-line scripts, requires socat

If you are familiar with pwntools, nclib provides much of the functionaly that
pwntools' socket wrappers do, but with the bonus feature of not being pwntools.

## Installation

`pip install nclib`

## Python examples

*Example 1:* Send a greeting to a UDP server listening at 192.168.3.6:8888 and log the
response as hex:

```python
>>> nc = nclib.Netcat(('192.168.3.6', 8888), udp=True, verbose=True)
>>> nc.echo_hex = True
>>> nc.echo_sending = False
>>> nc.send('Hello, world!')
>>> nc.recv_all()
```

The exhaustive list of logging options you can tweak is:

- `echo_headers` - Whether to print out messages describing the action taking place (default True)
- `echo_sending` - Whether to log sends (default True)
- `echo_recving` - Whether to log receives (default True)
- `echo_hex`     - Whether to log data hex-encoded (default False)
- `echo_perline` - Whether to format the output more nicely. With `echo_hex` off, it splits data by
                   lines and prefixes each line with either `>>` or `<<` for sending or receiving.
				   With `echo_hex` on, it formats the data like a hexdump.

All of the logging which is subject to the above options is mean to be informative to the user and happens on stdout. The default settings are meant to allow quick debugging of plain-text protocols.
There is an alternate form of logging which is meant to capture the data streams for later analysis or replay; this is through the `log_send` and `log_recv` constructor parameters.

*Example 2:* Listen for a local TCP connection on port 1234, allow the user to interact
with the client. Log the entire interaction to log.txt.

```python
>>> logfile = open('log.txt', 'wb')
>>> nc = nclib.Netcat(listen=('localhost', 1234), log_send=logfile, log_recv=logfile)
>>> nc.interact()
```

## serve-stdio

This is a simple command line wrapper for socat that can turn any program that
works over stdin/stdout. The -d flag will daemonize the server, printing out
its PID so you can kill it later.

```bash
$ sudo apt-get install socat
$ serve-stdio -d 1234 echo hey
13282
$ nc localhost 1234
hey
```

If you want the socket to see the process' stderr, you can redirect stderr
into stdout, but you have to do it quotatively, otherwise the redirect applies
to the socat process but not its children.

```bash
$ serve-stdio 1234 'strace echo hey 2>&1'
```
