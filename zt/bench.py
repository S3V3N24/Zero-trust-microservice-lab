"""Latency / throughput comparison: no security versus the zero-trust path (report Section 5.3).

  baseline      plain HTTP, no TLS, no identity, no policy, no logging
  zero-trust    mTLS 1.3 with identity checks + policy evaluation on every request (connections reused)
  zt, new conn  as above but a NEW mTLS handshake for every request (the worst case)

These numbers come from this Python prototype on this computer. They show the SHAPE of the
trade-off (security costs latency); they are not measurements of the Kubernetes testbed.
"""
from __future__ import annotations

import http.client
import json
import subprocess
import sys
import threading
import time

from .common import HOST, PORTS, ROOT
from .mesh import mesh_request
from .stack import port_open


def _percentile(sorted_values, p):
    return sorted_values[min(len(sorted_values) - 1, max(0, int(round(p * len(sorted_values) + 0.5)) - 1))]


def _measure(make_conn, threads: int, per_thread: int, fresh: bool = False) -> dict:
    latencies, errors, lock = [], [0], threading.Lock()

    def worker():
        conn, local = make_conn(), []
        for _ in range(per_thread):
            if fresh:
                conn.close()
                conn = make_conn()
            t0 = time.perf_counter()
            try:
                conn.request('GET', '/kv/bench')
                resp = conn.getresponse()
                resp.read()
                if resp.status != 200:
                    raise OSError('status %s' % resp.status)
            except (OSError, http.client.HTTPException):
                with lock:
                    errors[0] += 1
                conn = make_conn()
                continue
            local.append((time.perf_counter() - t0) * 1000)
        conn.close()
        with lock:
            latencies.extend(local)

    pool = [threading.Thread(target=worker) for _ in range(threads)]
    start = time.perf_counter()
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    wall = time.perf_counter() - start
    latencies.sort()
    return {'p50': _percentile(latencies, 0.50), 'p95': _percentile(latencies, 0.95),
            'p99': _percentile(latencies, 0.99), 'qps': len(latencies) / wall, 'errors': errors[0]}


def run_benchmark(lab, say=print, threads: int = 8, per_thread: int = 250) -> list:
    api = lab.identity('api')                     # same identity the real API replicas use
    status, _ = mesh_request(api, 'cache', 'PUT', '/kv/bench', {'value': 'x' * 2000})
    assert status == 200, 'could not seed the benchmark key'
    server = subprocess.Popen([sys.executable, '-m', 'zt.baseline'], cwd=str(ROOT),
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if port_open(PORTS['baseline']):
                break
            time.sleep(0.1)
        plain = lambda: http.client.HTTPConnection(HOST, PORTS['baseline'], timeout=5)
        secure = lambda: http.client.HTTPSConnection(HOST, PORTS['cache'], context=api.client_context, timeout=5)
        rows = []
        for label, factory, fresh, n in (
                ('baseline (plain HTTP)', plain, False, per_thread),
                ('zero-trust (mTLS + policy, reused connections)', secure, False, per_thread),
                ('zero-trust (new mTLS handshake per request)', secure, True, max(40, per_thread // 5))):
            say('  measuring: %s ...' % label)
            _measure(factory, 2, 20, fresh)       # warm-up
            rows.append((label, _measure(factory, threads, n, fresh)))
        return rows
    finally:
        server.terminate()
        api.stop()


def format_table(rows) -> str:
    base = rows[0][1]
    lines = ['| Scenario | P50 (ms) | P95 (ms) | P99 (ms) | Requests/s | P95 overhead |',
             '| --- | ---: | ---: | ---: | ---: | ---: |']
    for label, r in rows:
        extra = '-' if r is base else '+%.2f ms' % (r['p95'] - base['p95'])
        lines.append('| %s | %.2f | %.2f | %.2f | %.0f | %s |' % (label, r['p50'], r['p95'], r['p99'], r['qps'], extra))
    z = rows[1][1]
    lines.append('')
    lines.append('Throughput change with reused connections: %+.1f%%' % ((z['qps'] - base['qps']) / base['qps'] * 100))
    return '\n'.join(lines)
