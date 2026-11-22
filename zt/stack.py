"""Starts and stops the whole system: control plane + db, cache, api, gateway (one process each)."""
from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time

from .ca import attest_token
from .common import HOST, PORTS, ROOT, RUNTIME_DIR, SERVICES, SVID_TTL


def port_open(port: int) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=0.3):
            return True
    except OSError:
        return False


class Stack:
    def __init__(self, log_allow: bool = True, ttl: int | None = None):
        self.log_allow = log_allow
        self.ttl = ttl or SVID_TTL
        self.procs: dict = {}
        self._logs: list = []
        self.node_secret = secrets.token_hex(16)
        self.admin_token = secrets.token_hex(16)
        self.jwt_secret = secrets.token_hex(16)

    def _spawn(self, module: str, extra_env: dict):
        env = dict(os.environ)
        env.update({'ZT_NODE_SECRET': self.node_secret, 'ZT_ADMIN_TOKEN': self.admin_token,
                    'ZT_JWT_SECRET': self.jwt_secret, 'ZT_SVID_TTL': str(self.ttl),
                    'ZT_LOG_ALLOW': '1' if self.log_allow else '0', 'PYTHONUNBUFFERED': '1'})
        env.update(extra_env)
        log = open(RUNTIME_DIR / 'logs' / (module.split('.')[-1] + '.log'), 'w')
        self._logs.append(log)
        return subprocess.Popen([sys.executable, '-m', module], cwd=str(ROOT), env=env, stdout=log, stderr=log)

    def _wait(self, name: str, port: int, proc, timeout: float = 20.0):
        end = time.time() + timeout
        while time.time() < end:
            if proc.poll() is not None:
                tail = (RUNTIME_DIR / 'logs' / (name + '.log')).read_text()[-1200:]
                raise RuntimeError('%s exited during start-up:\n%s' % (name, tail))
            if port_open(port):
                return
            time.sleep(0.1)
        raise RuntimeError('%s did not open port %d in time' % (name, port))

    def start(self) -> 'Stack':
        busy = [n for n in ['controlplane', 'dashboard'] + SERVICES if port_open(PORTS[n])]
        if busy:
            raise RuntimeError('ports already in use for: %s. Stop the other run first, or set '
                               'ZT_PORT_OFFSET=100 to use different ports.' % ', '.join(busy))
        if RUNTIME_DIR.exists():
            shutil.rmtree(RUNTIME_DIR, ignore_errors=True)
        (RUNTIME_DIR / 'logs').mkdir(parents=True)
        secrets_file = RUNTIME_DIR / 'secrets.json'
        secrets_file.write_text(json.dumps({'admin_token': self.admin_token, 'jwt_secret': self.jwt_secret,
                                            'node_secret': self.node_secret}))
        try:
            os.chmod(secrets_file, 0o600)
        except OSError:
            pass
        self.procs['controlplane'] = self._spawn('zt.controlplane', {})
        self._wait('controlplane', PORTS['controlplane'], self.procs['controlplane'])
        for name in SERVICES:
            self.procs[name] = self._spawn('zt.services.' + name, {'ZT_ATTEST_TOKEN': attest_token(self.node_secret, name)})
            self._wait(name, PORTS[name], self.procs[name])
        return self

    def stop(self) -> None:
        for proc in self.procs.values():
            if proc.poll() is None:
                proc.terminate()
        for proc in self.procs.values():
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.procs.clear()
        for log in self._logs:
            log.close()
        self._logs.clear()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
