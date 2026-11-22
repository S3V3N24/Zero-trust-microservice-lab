"""Runtime security sentinel: a small, portable stand-in for Falco (report Sections 2.6, 4.5, 4.13).

Falco watches *system calls* from the Linux kernel through eBPF. This prototype has no
kernel component; instead it subscribes to Python's audit hooks (PEP 578), which report the
same kinds of events from inside the process: starting a program, opening a file, opening a
network connection. Rules are evaluated on every event, alerts are written to the audit log,
and CRITICAL alerts trigger the automatic response (quarantine + identity revocation).

Rules (names follow the report's Falco rules):
  ZTA Shell Spawned in Microservice Container    CRITICAL  T1059.004
  ZTA Credential File Read by Application        CRITICAL  T1552.001 / T1552.007
  ZTA Unexpected Outbound Connection             CRITICAL  T1041   (connection is also BLOCKED)
  ZTA Package Manager or Downloader Executed     WARNING   T1105
"""
from __future__ import annotations

import ipaddress
import os
import sys
import threading

from .common import audit

SHELLS = {'sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh'}
TOOLING = {'apt', 'apt-get', 'dpkg', 'yum', 'dnf', 'apk', 'pip', 'pip3', 'npm', 'curl', 'wget'}


def _is_loopback(host: str) -> bool:
    if host in ('localhost', ''):
        return True
    try:
        return ipaddress.ip_address(host.split('%')[0]).is_loopback
    except ValueError:
        return False


class Sentinel:
    _installed = False

    def __init__(self, service: str, on_critical=None):
        self.service = service
        self.on_critical = on_critical
        self._tl = threading.local()

    def install(self) -> None:
        if Sentinel._installed:
            return
        Sentinel._installed = True
        sys.addaudithook(self._hook)

    # ---- the audit hook ----------------------------------------------------------------
    def _hook(self, event: str, args) -> None:
        if getattr(self._tl, 'busy', False):        # never inspect our own logging activity
            return
        try:
            if event == 'subprocess.Popen':
                executable, argv = args[0], args[1]
                name = os.path.basename(str(executable or (argv[0] if argv else ''))).lower()
                self._process(name, ' '.join(map(str, argv)) if argv else name)
            elif event == 'os.system':
                self._process('sh', str(args[0]))
            elif event == 'open':
                path = args[0]
                if isinstance(path, (str, bytes, os.PathLike)):
                    text = os.fsdecode(path).replace('\\', '/')
                    if 'decoy_secrets' in text:
                        self._alert('ZTA Credential File Read by Application', 'CRITICAL',
                                    'file=%s' % os.path.basename(text), 'T1552.001')
            elif event == 'socket.connect':
                address = args[1]
                if isinstance(address, tuple) and address and isinstance(address[0], str):
                    if not _is_loopback(address[0]):
                        self._alert('ZTA Unexpected Outbound Connection', 'CRITICAL',
                                    'dst=%s:%s (blocked)' % (address[0], address[1] if len(address) > 1 else '?'),
                                    'T1041')
                        raise PermissionError('egress blocked by zero-trust policy')
        except PermissionError:
            raise
        except Exception:                           # a bug in a rule must never crash the service
            pass

    def _process(self, name: str, cmdline: str) -> None:
        if name in SHELLS:
            self._alert('ZTA Shell Spawned in Microservice Container', 'CRITICAL', 'cmd=%s' % cmdline, 'T1059.004')
        elif name in TOOLING:
            self._alert('ZTA Package Manager or Downloader Executed', 'WARNING', 'cmd=%s' % cmdline, 'T1105')

    def _alert(self, rule: str, priority: str, detail: str, mitre: str) -> None:
        self._tl.busy = True
        try:
            audit(self.service, 'alert', rule=rule, priority=priority, detail=detail, mitre=mitre)
            sys.stderr.write('[sentinel:%s] %s %s %s\n' % (self.service, priority, rule, detail))
            if priority == 'CRITICAL' and self.on_critical:
                self.on_critical(rule)
        finally:
            self._tl.busy = False
