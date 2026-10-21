# Tor monitoring for Zabbix 7.4

Monitor local C Tor with classic Zabbix agent (`zabbix_agentd`) or Zabbix agent2 **active checks**, one loopback HTTP scrape per minute, and native Zabbix Prometheus preprocessing. No Prometheus server, Tor ControlPort access, root execution, curl, or third-party Python modules are required.

Developed from a Tor **0.4.9.11** metrics sample. Older versions may omit metrics; unsupported/missing series are discarded, never replaced with healthy-looking zeroes. The template does not depend on systemd; the commands below use it only to restart the packaged agent.

## Install

Enable the metrics endpoint in the Tor instance's torrc:

```conf
MetricsPort 127.0.0.1:9035
MetricsPortPolicy accept 127.0.0.1
```

Apply the Tor configuration using your normal service manager. Confirm:

```bash
curl -fsS http://127.0.0.1:9035/metrics
```

Both agents use the same Python collector, UserParameter and active-check template. Prometheus preprocessing and onion discovery run on the Zabbix server/proxy, so no Agent2 plugin is needed. Use a supported agent release; this does not add compatibility with old Zabbix servers (the template requires Zabbix 7.4).

From the unpacked project directory, first install the shared collector:

```bash
sudo install -d -m 0755 /etc/zabbix/scripts
sudo install -m 0755 scripts/tor_prometheus.py /etc/zabbix/scripts/tor_prometheus.py
sudo -u zabbix /usr/bin/python3 /etc/zabbix/scripts/tor_prometheus.py 9035
```

Then choose the instructions for your installed agent. Do not install two copies of the UserParameter into the same agent's Include paths.

### Zabbix agent2

```bash
sudo install -d -m 0755 /etc/zabbix/zabbix_agent2.d
sudo install -m 0644 zabbix_agent2.d/tor.conf /etc/zabbix/zabbix_agent2.d/tor.conf
sudo zabbix_agent2 -T
sudo systemctl restart zabbix-agent2
zabbix_agent2 -t 'tor.prometheus[9035]'
```

Ensure `/etc/zabbix/zabbix_agent2.conf` includes `Include=/etc/zabbix/zabbix_agent2.d/*.conf`.

### Classic Zabbix agent (zabbix_agentd)

```bash
sudo install -d -m 0755 /etc/zabbix/zabbix_agentd.d
sudo install -m 0644 zabbix_agentd.d/tor.conf /etc/zabbix/zabbix_agentd.d/tor.conf
sudo systemctl restart zabbix-agent
zabbix_agentd -c /etc/zabbix/zabbix_agentd.conf -t 'tor.prometheus[9035]'
```

Ensure `/etc/zabbix/zabbix_agentd.conf` includes:

```conf
Include=/etc/zabbix/zabbix_agentd.d/*.conf
```

Package-specific include directories, executable paths and service names can differ. For example, some distributions use `/etc/zabbix/zabbix_agentd.conf.d/`; install `tor.conf` into the directory your configuration actually includes. On Void Linux, use its service manager instead of the `systemctl` command and run the collector check as `_zabbix_agent` if that is the configured agent account.

### Shared active-check configuration and import

For either agent, configure the correct `ServerActive` and `Hostname` for your Zabbix host. The collector uses a two-second socket timeout; the agent's default three-second check timeout is normally sufficient on loopback. Large installations can set `Timeout=5`.

In **Data collection → Templates**, import `Template_Tor_Agent2.yaml`, then link **Template App Tor by Zabbix agent active** to the host. Allow a few collection intervals for discovery and rate data. The YAML filename and internal template identifier retain their original Agent2 naming for update compatibility; both agent implementations use this same template. Existing imports can be updated using the same UUIDs.

## Macros

| Macro | Default | Meaning |
|---|---|---|
| `{$TOR.METRICS.PORT}` | `9035` | Local IPv4 loopback MetricsPort |
| `{$TOR.RELAY.REQUIRED}` | `0` | Set `1` only if this instance must be a public relay with the consensus Running flag |
| `{$TOR.SOCKETS.WARN.PCT}` | `80` | Socket utilization warning threshold |
| `{$TOR.ONION.INTRO.MIN}` | `1` | Minimum introduction circuits per discovered onion service; `0` disables the low-count alert |

One instance per host is covered by this initial template. Multiple onion services within that instance are discovered automatically; no address list is needed.

## Collected data

23 static items cover endpoint availability/status/latency, sockets and utilization, circuits, OR and SOCKS connections, relay Running flag, bandwidth, internal bugs, OOM bytes freed, TCP port exhaustion, DNS queries/errors, DoS defenses, onionskin drops, rejected connections and configured bandwidth-limit events.

Each discovered onion service gets 10 items: introduction/rendezvous circuits, introduction and rendezvous creation rates, error rates, application read/write bandwidth, PoW queue and effort. Application bandwidth sums all virtual ports for that onion. Service discovery uses the native `Prometheus to JSON` preprocessing and the `onion` label. Two graph prototypes show per-service circuits and bandwidth; three global graphs show traffic, connections and sockets.

Triggers cover:

- metrics endpoint unavailable for three minutes;
- no monitoring data for five minutes (including stopped agent);
- socket utilization over threshold for five minutes;
- internal bugs, OOM reclamation or TCP port exhaustion increasing within ten minutes;
- no introduction circuits for five minutes, with at least five observations;
- a discovered service's introduction metrics missing for ten minutes while collection is working;
- optionally, a relay lacking the Running flag for fifteen minutes.

Rate-limit events and DoS counters are recorded without default alerts: some are expected during normal operation. Zero rendezvous circuits or traffic on an idle onion service is normal. All operational alerts are gated on a recent successful metrics scrape. Missing optional series remain gaps; inspect Latest data and endpoint output when upgrading Tor.

Discovery runs with each successful master sample. A failed scrape is discarded for discovery so outages do not erase the service list. Removed services remain as lost resources for seven days; the missing-metrics alert can fire during that retention period. Delete obsolete discovered resources if removal was intentional.

## Counter and scrape behavior

Counters use `CHANGE_PER_SECOND`. Zabbix ignores a decreasing counter sample and establishes a fresh baseline after reset; the first sample produces no rate. A scrape outage emits only synthetic collector status, so Tor counters are never reset to artificial zero. The next rate may represent the average over the collection gap; independent Tor counters can reset between scrapes without being detectable if they already exceed the old value.

The collector normalizes repeated HELP/TYPE metadata emitted per onion service, because duplicate metadata can break Zabbix parsing. It renames only the **unlabelled** `tor_relay_load_socket_total` sample to `zbx_tor_socket_limit`; in C Tor this is `get_max_sockets()`. The labelled `state="opened"` sample remains unchanged. Thus the socket limit is never added to the open-socket count. All other samples, labels and histogram buckets are preserved. The first release does not turn histogram buckets into latency percentiles.

A scrape has a 4 MiB limit and uses no proxy or HTTP redirects. There is no authentication token: access is governed by Tor's loopback bind and MetricsPortPolicy. Do not expose MetricsPort publicly. Onion identifiers appear in discovered Zabbix items; restrict Zabbix access accordingly. Raw scrape history is disabled.

## Scope and validation

Metrics indicate local Tor state, **not end-to-end reachability**. They do not prove that SOCKS can reach the network, that an onion descriptor is published, or that the backend application responds. Add a separate external onion/SOCKS probe for those guarantees.

Tests cover successful and failed collection, malformed/oversize responses, redirect rejection, metadata normalization, socket separation and template selectors against an anonymized Tor 0.4.9.11 fixture. JavaScript preprocessing is exercised with Node. YAML, UUIDs and references are checked locally. An actual Zabbix server import, execution by installed agent binaries, and live trigger execution have **not** been tested in this environment. Both agent configurations invoke exactly the same tested collector.

Run:

```bash
python3 -m unittest discover -s tests -v
```

Collector tests require Python 3 only. Template checks additionally require PyYAML and Node.js; these are development dependencies, not runtime requirements.

References:

- https://support.torproject.org/relays/performance/overloaded/
- https://tpo.pages.torproject.net/core/doc/tor/relay__metrics_8c_source.html
- https://www.zabbix.com/documentation/7.4/en/manual/config/items/itemtypes/http/prometheus
- https://www.zabbix.com/documentation/7.4/en/manual/discovery/low_level_discovery/examples/prometheus
- Architecture reference: https://github.com/kristapsk/zbx-openclaw/

Classic agent UserParameter reference: https://www.zabbix.com/documentation/7.4/en/manual/config/items/userparameters
