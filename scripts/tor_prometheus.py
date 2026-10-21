#!/usr/bin/env python3
"""Fetch local C Tor metrics once; preserve native Prometheus samples."""
import re
import sys
import time
import urllib.request

MAX_BYTES = 4 * 1024 * 1024


def normalize(text):
    lines, metadata = [], set()
    for line in text.splitlines():
        if line.startswith(('# HELP ', '# TYPE ')):
            identity = tuple(line.split(' ', 3)[:3])
            if identity in metadata:
                continue
            metadata.add(identity)
        # C Tor exposes its maximum as an unlabelled sample of the same name.
        # Give it a distinct name so it cannot be confused with opened sockets.
        if re.match(r'^tor_relay_load_socket_total\s', line):
            line = line.replace('tor_relay_load_socket_total', 'zbx_tor_socket_limit', 1)
        lines.append(line)
    if not any(re.match(r'^tor_[a-zA-Z0-9_]+(?:\{|\s)', x) for x in lines):
        raise ValueError('No Tor samples')
    return '\n'.join(lines) + '\n'


def collect(port):
    start = time.monotonic()
    ok, status, body = 0, 0, ''
    try:
        if not re.fullmatch(r'[0-9]{1,5}', port) or not 1 <= int(port) <= 65535:
            raise ValueError('Invalid port')
        # Ignore proxy environment; never forward local metrics to a proxy.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open('http://127.0.0.1:' + port + '/metrics', timeout=2) as response:
            status = response.status
            payload = response.read(MAX_BYTES + 1)
            if status != 200 or len(payload) > MAX_BYTES:
                raise ValueError('Invalid response')
            body = normalize(payload.decode('utf-8'))
            ok = 1
    except (OSError, ValueError, UnicodeError) as error:
        status = getattr(error, 'code', status)
    elapsed = (time.monotonic() - start) * 1000
    return body + ('zbx_tor_metrics_ok %d\nzbx_tor_http_status %d\n'
                   'zbx_tor_scrape_duration_ms %.3f\n' % (ok, status, elapsed))


if __name__ == '__main__':
    print(collect(sys.argv[1] if len(sys.argv) == 2 else '9035'), end='')
