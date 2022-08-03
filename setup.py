long_description = '''
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

Documentation is available at https://nclib.readthedocs.io/ and source code is
available at https://github.com/rhelmot/nclib

If you are familiar with pwntools, nclib provides much of the functionaly that
pwntools' socket wrappers do, but with the bonus feature of not being pwntools.
'''

if bytes is str:
  raise Exception("nclib is python 3 only now :(")

from setuptools import setup
setup(name='nclib',
      version='1.0.2',
      python_requires='>=3.5',
      packages=['nclib'],
      scripts=['serve-stdio'],
      description='Netcat as a library: convienent socket interfaces',
      long_description=long_description,
      url='https://github.com/rhelmot/nclib',
      author='rhelmot',
      author_email='audrey@rhelmot.io',
      license='MIT',
      keywords='netcat nc socket sock file pipe tcp udp recv until logging interact handle listen connect server serve stdio process gdb'
      )
