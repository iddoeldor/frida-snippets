"""
Execute shell command
For example, list directory contents:
def ls(folder):
    cmd = Shell(['/bin/sh', '-c', 'ls -la ' + folder], None)
    cmd.exec()
    for chunk in cmd.output:
        print(chunk.strip().decode())
"""
import frida
from frida_tools.application import Reactor
import threading
import click


class Shell(object):
    def __init__(self, argv, env):
        self._stop_requested = threading.Event()
        self._reactor = Reactor(run_until_return=lambda reactor: self._stop_requested.wait())

        self._device = frida.get_usb_device()
        self._sessions = set()

        self._device.on("child-added", lambda child: self._reactor.schedule(lambda: self._on_child_added(child)))
        self._device.on("child-removed", lambda child: self._reactor.schedule(lambda: self._on_child_removed(child)))
        self._device.on("output", lambda pid, fd, data: self._reactor.schedule(lambda: self._on_output(pid, fd, data)))

        self.argv = argv
        self.env = env
        self.output = []  # stdout will pushed into array

    def exec(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def _start(self):
        click.secho("✔ spawn(argv={})".format(self.argv), fg='green', dim=True)
        pid = self._device.spawn(self.argv, env=self.env, stdio='pipe')
        self._instrument(pid)

    def _stop_if_idle(self):
        if len(self._sessions) == 0:
            self._stop_requested.set()

    def _instrument(self, pid):
        click.secho("✔ attach(pid={})".format(pid), fg='green', dim=True)
        session = self._device.attach(pid)
        session.on("detached", lambda reason: self._reactor.schedule(lambda: self._on_detached(pid, session, reason)))
        click.secho("✔ enable_child_gating()", fg='green', dim=True)
        session.enable_child_gating()
        # print("✔ resume(pid={})".format(pid))
        self._device.resume(pid)
        self._sessions.add(session)

    def _on_child_added(self, child):
        click.secho("⚡ child_added: {}".format(child), fg='green', dim=True)
        self._instrument(child.pid)

    @staticmethod
    def _on_child_removed(child):
        click.secho("⚡ child_removed: {}".format(child), fg='green', dim=True)

    def _on_output(self, pid, fd, data):
        # print("⚡ output: pid={}, fd={}, data={}".format(pid, fd, repr(data)))
        # fd=0 (input) fd=1(stdout) fd=2(stderr)
        if fd != 2:
            self.output.append(data)

    def _on_detached(self, pid, session, reason):
        click.secho("⚡ detached: pid={}, reason='{}'".format(pid, reason), fg='green', dim=True)
        self._sessions.remove(session)
        self._reactor.schedule(self._stop_if_idle, delay=0.5)

    @staticmethod
    def _on_message(pid, message):
        click.secho("⚡ message: pid={}, payload={}".format(pid, message), fg='green', dim=True)
