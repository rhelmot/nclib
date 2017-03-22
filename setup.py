long_description = '''
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

run help(nclib) for help.

If you are familiar with pwntools, nclib provides much of the functionaly that
pwntools' socket wrappers do, but with the bonus feature of not being pwntools.
'''

from setuptools import setup
setup(name='nclib',
      version='0.6.0',
      py_modules=['nclib'],
      scripts=['serve-stdio'],
      description='Netcat as a library: convienent socket interfaces',
      long_description=long_description,
      url='https://github.com/rhelmot/nclib',
      author='Andrew Dutcher',
      author_email='andrewrdutcher@gmail.com',
      license='MIT',
      keywords='netcat nc socket tcp udp recv until logging interact handle listen connect serve stdio'
      )
