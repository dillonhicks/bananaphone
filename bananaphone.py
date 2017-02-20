#!/usr/bin/env python
import argparse
import atexit
import fcntl
import grp
import logging
import pwd
import resource
import signal
import sys
import threading
import traceback
from datetime import datetime
from logging import handlers
from socket import SOL_SOCKET
from socket import SO_REUSEADDR
from socket import socket

from six.moves.socketserver import TCPServer, BaseRequestHandler

import os
import tempfile
import six


LOCALHOST = '127.0.0.1'
DEFAULT_TIMEOUT = 300  # Seconds
LOG = logging.getLogger('bananaphone')


class Daemonize(object):
    """
    Daemonize object.

    Object constructor expects three arguments.

    :param app: contains the application name which will be sent to syslog.
    :param pid: path to the pidfile.
    :param action: your custom function which will be executed after daemonization.
    :param keep_fds: optional list of fds which should not be closed.
    :param auto_close_fds: optional parameter to not close opened fds.
    :param privileged_action: action that will be executed before drop privileges if user or
                              group parameter is provided.
                              If you want to transfer anything from privileged_action to action, such as
                              opened privileged file descriptor, you should return it from
                              privileged_action function and catch it inside action function.
    :param user: drop privileges to this user if provided.
    :param group: drop privileges to this group if provided.
    :param verbose: send debug messages to logger if provided.
    :param logger: use this logger object instead of creating new one, if provided.
    :param foreground: stay in foreground; do not fork (for debugging)
    :param chdir: change working directory if provided or /

    ---

    Copyright (c) 2012, 2013, 2014 Ilya Otyutskiy <ilya.otyutskiy@icloud.com>

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
    documentation files (the "Software"), to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
    to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial
    portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
    CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
    """
    def __init__(self, app, pid, action,
                 keep_fds=None, auto_close_fds=True, privileged_action=None,
                 user=None, group=None, verbose=False, logger=None,
                 foreground=False, chdir=None):
        self.app = app
        self.pid = os.path.abspath(pid)
        self.action = action
        self.keep_fds = keep_fds or []
        self.privileged_action = privileged_action or (lambda: ())
        self.user = user
        self.group = group
        self.logger = logger
        self.verbose = verbose
        self.auto_close_fds = auto_close_fds
        self.foreground = foreground
        self.chdir = chdir if chdir is not None else os.getcwd()

    def sigterm(self, signum, frame):
        """
        These actions will be done after SIGTERM.
        """
        self.logger.warning("Caught signal %s. Stopping daemon.", signum)
        sys.exit(0)

    def exit(self):
        """
        Cleanup pid file at exit.
        """
        self.logger.info("Stopping daemon")
        os.remove(self.pid)
        sys.exit(0)

    def start(self):
        """
        Start daemonization process.
        """
        # If pidfile already exists, we should read pid from there; to overwrite it, if locking
        # will fail, because locking attempt somehow purges the file contents.
        if os.path.isfile(self.pid):
            with open(self.pid, "r") as old_pidfile:
                old_pid = old_pidfile.read()
        # Create a lockfile so that only one instance of this daemon is running at any time.
        try:
            lockfile = open(self.pid, "w")
        except IOError:
            print("Unable to create the pidfile.")
            sys.exit(1)
        try:
            # Try to get an exclusive lock on the file. This will fail if another process has the file
            # locked.
            fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            print("Unable to lock on the pidfile.")
            # We need to overwrite the pidfile if we got here.
            with open(self.pid, "w") as pidfile:
                pidfile.write(old_pid)
            sys.exit(1)

        # skip fork if foreground is specified
        if not self.foreground:
            # Fork, creating a new process for the child.
            try:
                process_id = os.fork()
            except OSError as e:
                self.logger.error("Unable to fork, errno: {0}".format(e.errno))
                sys.exit(1)
            if process_id != 0:
                # This is the parent process. Exit without cleanup,
                # see https://github.com/thesharp/daemonize/issues/46
                os._exit(0)
            # This is the child process. Continue.

            # Stop listening for signals that the parent process receives.
            # This is done by getting a new process id.
            # setpgrp() is an alternative to setsid().
            # setsid puts the process in a new parent group and detaches its controlling terminal.
            process_id = os.setsid()
            if process_id == -1:
                # Uh oh, there was a problem.
                sys.exit(1)

            # Add lockfile to self.keep_fds.
            self.keep_fds.append(lockfile.fileno())

            # Close all file descriptors, except the ones mentioned in self.keep_fds.
            devnull = "/dev/null"
            if hasattr(os, "devnull"):
                # Python has set os.devnull on this system, use it instead as it might be different
                # than /dev/null.
                devnull = os.devnull

            if self.auto_close_fds:
                for fd in range(3, resource.getrlimit(resource.RLIMIT_NOFILE)[0]):
                    if fd not in self.keep_fds:
                        try:
                            os.close(fd)
                        except OSError:
                            pass

            devnull_fd = os.open(devnull, os.O_RDWR)
            os.dup2(devnull_fd, 0)
            os.dup2(devnull_fd, 1)
            os.dup2(devnull_fd, 2)
            os.close(devnull_fd)

        if self.logger is None:
            # Initialize logging.
            self.logger = logging.getLogger(self.app)
            self.logger.setLevel(logging.DEBUG)
            # Display log messages only on defined handlers.
            self.logger.propagate = False

            # Initialize syslog.
            # It will correctly work on OS X, Linux and FreeBSD.
            if sys.platform == "darwin":
                syslog_address = "/var/run/syslog"
            else:
                syslog_address = "/dev/log"

            # We will continue with syslog initialization only if actually have such capabilities
            # on the machine we are running this.
            if os.path.exists(syslog_address):
                syslog = handlers.SysLogHandler(syslog_address)
                if self.verbose:
                    syslog.setLevel(logging.DEBUG)
                else:
                    syslog.setLevel(logging.INFO)
                # Try to mimic to normal syslog messages.
                formatter = logging.Formatter("%(asctime)s %(name)s: %(message)s",
                                              "%b %e %H:%M:%S")
                syslog.setFormatter(formatter)

                self.logger.addHandler(syslog)

        # Set umask to default to safe file permissions when running as a root daemon. 027 is an
        # octal number which we are typing as 0o27 for Python3 compatibility.
        os.umask(0o27)

        # Change to a known directory. If this isn't done, starting a daemon in a subdirectory that
        # needs to be deleted results in "directory busy" errors.
        os.chdir(self.chdir)

        # Execute privileged action
        privileged_action_result = self.privileged_action()
        if not privileged_action_result:
            privileged_action_result = []

        # Change owner of pid file, it's required because pid file will be removed at exit.
        uid, gid = -1, -1

        if self.group:
            try:
                gid = grp.getgrnam(self.group).gr_gid
            except KeyError:
                self.logger.error("Group {0} not found".format(self.group))
                sys.exit(1)

        if self.user:
            try:
                uid = pwd.getpwnam(self.user).pw_uid
            except KeyError:
                self.logger.error("User {0} not found.".format(self.user))
                sys.exit(1)

        if uid != -1 or gid != -1:
            os.chown(self.pid, uid, gid)

        # Change gid
        if self.group:
            try:
                os.setgid(gid)
            except OSError:
                self.logger.error("Unable to change gid.")
                sys.exit(1)

        # Change uid
        if self.user:
            try:
                uid = pwd.getpwnam(self.user).pw_uid
            except KeyError:
                self.logger.error("User {0} not found.".format(self.user))
                sys.exit(1)
            try:
                os.setuid(uid)
            except OSError:
                self.logger.error("Unable to change uid.")
                sys.exit(1)

        try:
            lockfile.write("%s" % (os.getpid()))
            lockfile.flush()
        except IOError:
            self.logger.error("Unable to write pid to the pidfile.")
            print("Unable to write pid to the pidfile.")
            sys.exit(1)

        # Set custom action on SIGTERM.
        signal.signal(signal.SIGTERM, self.sigterm)
        atexit.register(self.exit)

        self.logger.info("Starting daemon")

        try:
            self.action(*privileged_action_result)
        except Exception:
            for line in traceback.format_exc().split("\n"):
                self.logger.error(line)


def _reserve_port(ip=LOCALHOST):
    """Bind to an ephemeral port, force it into the TIME_WAIT state, and unbind it.

    This means that further ephemeral port allocations won't pick this "reserved" port,
    but subprocesses can still bind to it explicitly, given that they use SO_REUSEADDR.
    By default on linux you have a grace period of 60 seconds to reuse this port.
    To check your own particular value:
    $ cat /proc/sys/net/ipv4/tcp_fin_timeout
    60

    By default, the port will be reserved for localhost (aka 127.0.0.1).
    To reserve a port for a different ip, provide the ip as the first argument.
    Note that IP 0.0.0.0 is interpreted as localhost.

    ---

    The MIT License (MIT)

    Copyright (c) 2016 Yelp

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
    """
    s = socket()
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.bind((ip, 0))

    # the connect below deadlocks on kernel >= 4.4.0 unless this arg is great than zero
    s.listen(1)
    sockname = s.getsockname()

    # these three are necessary just to get the port into a TIME_WAIT state
    s2 = socket()
    s2.connect(sockname)
    s.accept()

    return sockname[1]


def _one_shot_server(data, port):
    # type: (six.binary_type, six.integer_types) -> None
    """
    Setup a simple TCP server on localhost:<port> which will respond to
    the first request with <data> and then exit.
    """
    class Handler(BaseRequestHandler):
        def handle(self):
            LOG.info('Request received')
            self.request.recv(0)
            LOG.info('Sending %i bytes', len(data))
            self.request.sendall(data)
            LOG.info('Killing server')
            if six.PY3:
                signal.pthread_kill(threading.main_thread().ident, signal.SIGTERM)
            else:
                sys.exit(0)

    class Server(TCPServer):
        allow_reuse_address = True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.server_close()

    with Server((LOCALHOST, port), Handler) as server:
        Handler.server = server
        LOG.info('Listening on %s', server.server_address)
        server.serve_forever()


def daemon(args):
    parser = argparse.ArgumentParser(
        prog='bananaphone',
        description='Expose an ephemeral port on localhost as a '
                    'one-shot credserver for docker',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        help='Turn on debugging and run the daemon in the foreground')

    parser.add_argument('-f', '--file', type=str, dest='path', required=True,
                       help='The file containing credentials serve on the port')

    parser.add_argument('-t', '--timeout', type=int, dest='timeout', default=DEFAULT_TIMEOUT,
                        help='Specify a non default timeout (in seconds) '
                             'for the bananaphone before hanging up.')

    today = datetime.today().strftime('%Y-%m-%d')
    parser.add_argument('-l', '--logfile', type=str, dest='logfile',
                        default='./bananaphone.{}.log'.format(today),
                        help='Override the filepath for the bananaphone daemon log.')
    args = parser.parse_args(args)

    pidfile = tempfile.NamedTemporaryFile(suffix='bananaphone.pid').name
    logfile = args.logfile
    with open(args.path, 'r+b') as infile:
        data = infile.read()

    timeout = args.timeout


    fmt = logging.Formatter(
        fmt='%(asctime)s|%(process)d|%(levelname)-7s| %(message)s',
        datefmt='%H:%M:%S')
    fh = logging.FileHandler(logfile)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    LOG.setLevel(logging.DEBUG)
    LOG.propagate = False
    LOG.addHandler(fh)
    keep_fds = [fh.stream.fileno()]

    # Reserve Ephemeral Port and write it to stdout before
    # daemonizing the credserver and effectively sending it
    # to the background.
    port = _reserve_port(LOCALHOST)
    sys.stdout.write(str(port))
    sys.stdout.flush()

    daemon = Daemonize('bananaphone', str(pidfile), lambda: action(), logger=LOG, foreground=args.debug, keep_fds=keep_fds)


    def action():
        LOG.debug('Arguments: %s', args)

        def alarm_timeout_handler(signum, frame):
            LOG.warn('Process timed out after %0.f seconds', timeout)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
            signal.alarm(0)

            if six.PY3:
                signal.pthread_kill(threading.main_thread().ident, signal.SIGTERM)
            else:
                sys.exit(1)

        if six.PY3:
            signal.signal(signal.SIGALRM, alarm_timeout_handler)
            signal.alarm(timeout)
        else:
            signal.signal(signal.SIGALRM, alarm_timeout_handler)
            signal.alarm(timeout)

        _one_shot_server(data, port)

    daemon.start()


if __name__ == '__main__':
    daemon(sys.argv[1:])
