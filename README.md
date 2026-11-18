# geoblock

A small Go service that watches IPv4 traffic on one network interface, looks
up the country of every remote address and drops traffic to and from
countries you list, using local iptables rules. Traffic counters per country
and direction are exported for Prometheus.

The repository is still called `go_prometheus_packet_monitoring`; the binary
is `geoblock`.

## How it works

```
                 libpcap (BPF filter excludes Redis, lookup API, loopback)
                                   |
                                   v
 capture loop ── classify packet: which side is remote? public address?
      |                     |
      |  (memory cache hit) |  (miss: non-blocking, deduplicated enqueue)
      v                     v
 Prometheus counters    lookup workers ── memory ─> Redis (TTL) ─> ip-api (rate limited)
                                   |
                                   v
                     country blocked? ── iptables INPUT -s / OUTPUT -d DROP (once per IP)
```

- **Capture** reads only the first 128 bytes of each packet and decodes the
  link and IPv4 headers. The BPF filter keeps the program's own Redis and API
  traffic out of the capture, so lookups cannot generate more lookups.
- **Classification** picks the remote side of each packet: if the source is one
  of the interface's addresses the packet is outbound, if the destination is,
  it is inbound. Private, loopback, link-local, multicast, broadcast,
  unspecified and other reserved addresses are ignored entirely, as is traffic
  that neither starts nor ends on this host.
- **Lookup** never happens on the capture path. The capture loop only checks
  an in-process cache; unknown addresses go into a bounded queue that holds
  each address at most once. Background workers check memory, then Redis,
  then the ip-api HTTP API. Successful answers are stored in Redis with a TTL.
  Failed lookups are not cached and are retried after five minutes.
- **Blocking** inserts `-I INPUT 1 -s <ip> -j DROP` and
  `-I OUTPUT 1 -d <ip> -j DROP` the first time an address from a blocked
  country is resolved. Already-blocked addresses are tracked in memory and
  existing rules are detected with `iptables -C`, so rules are never
  duplicated, including after a restart.

Code layout:

| Package              | Responsibility                                            |
|----------------------|-----------------------------------------------------------|
| `cmd/geoblock`       | flags, wiring, HTTP server, graceful shutdown             |
| `internal/config`    | load, default and validate the JSON config                |
| `internal/capture`   | libpcap capture loop and BPF filter                       |
| `internal/netclass`  | remote-side and public-address classification             |
| `internal/geo`       | memory cache, Redis cache, ip-api client, lookup chain    |
| `internal/firewall`  | iptables rules (and a dry-run implementation)             |
| `internal/monitor`   | per-packet handling, lookup queue, block policy           |
| `internal/metrics`   | Prometheus collectors                                     |

## Configuration

The config file defaults to `$XDG_CONFIG_HOME/goPrometheusPacketMonitoring/config.json`
(usually `~/.config/...`); pass `-config <path>` to use another file. If the file
does not exist, an example is written there (mode 0600) and the program exits.

```json
{
  "InterfaceName": "eth0",
  "RedisDataBaseAddress": "127.0.0.1:6379",
  "RedisCacheTTL": "168h",
  "ListOfBlockedCountryCodes": ["CN", "RU"],
  "ListenAddress": ":2115",
  "LookupBaseURL": "http://ip-api.com",
  "LookupRequestsPerMinute": 40,
  "DryRun": false
}
```

| Field                       | Required | Default             | Meaning                                                   |
|-----------------------------|----------|---------------------|-----------------------------------------------------------|
| `InterfaceName`             | yes      |                     | Interface to capture on                                   |
| `RedisDataBaseAddress`      | yes      |                     | Redis `host:port`                                         |
| `RedisPassword`             | no       | empty               | Redis password                                            |
| `RedisCacheTTL`             | no       | `168h`              | How long a resolved country is cached in Redis            |
| `ListOfBlockedCountryCodes` | no       | empty               | ISO 3166-1 alpha-2 codes; case-insensitive                |
| `ListenAddress`             | no       | `:2115`             | Address for `/metrics` and `/healthz`                     |
| `LookupBaseURL`             | no       | `http://ip-api.com` | Any ip-api compatible endpoint (useful for testing)       |
| `LookupRequestsPerMinute`   | no       | `40`                | Client-side rate limit; the free tier allows 45           |
| `DryRun`                    | no       | `false`             | Log block decisions instead of changing iptables          |

Config files from earlier versions keep working: the original field names are
unchanged and the new fields are optional. Old Redis entries (keyed by bare IP,
without TTL) are not reused; new entries are stored under `geoblock:location:<ip>`.

Flags: `-config <path>`, `-log-level debug|info|warn|error`.

## Metrics

All label values are bounded: `direction` is `in` or `out`, `country` is an ISO
code or `unknown` (not resolved yet). There are no per-IP labels.

| Metric                                         | Type    | Labels              |
|------------------------------------------------|---------|---------------------|
| `geoblock_bytes_total`                         | counter | `direction`, `country` |
| `geoblock_packets_total`                       | counter | `direction`, `country` |
| `geoblock_blocked_ips_total`                   | counter |                     |
| `geoblock_lookups_total`                       | counter | `source` (`memory`, `redis`, `api`), `result` (`ok`, `miss`, `error`) |
| `geoblock_lookup_queue_dropped_total`          | counter |                     |

Go runtime and process metrics are exported as well.

Example PromQL:

```promql
# Inbound bandwidth per country, bytes per second
sum by (country) (rate(geoblock_bytes_total{direction="in"}[5m]))

# Top 5 countries by outbound packets in the last hour
topk(5, sum by (country) (increase(geoblock_packets_total{direction="out"}[1h])))

# Share of lookups that had to go to the external API
sum(rate(geoblock_lookups_total{source="api"}[15m]))
  / sum(rate(geoblock_lookups_total{result!="miss"}[15m]))

# Addresses blocked today
increase(geoblock_blocked_ips_total[24h])

# Lookup errors (API failures, rate limiting, Redis problems)
sum by (source) (rate(geoblock_lookups_total{result="error"}[5m]))
```

## Running

### Binary

Requires Go 1.26+, a C compiler and the libpcap headers (`libpcap-dev` on
Debian/Ubuntu, `libpcap` on Arch).

```sh
go build -o geoblock ./cmd/geoblock
sudo ./geoblock -config /etc/geoblock/config.json
```

Instead of running as root, the binary can be given the two capabilities it
needs:

```sh
sudo setcap cap_net_raw,cap_net_admin+ep ./geoblock
```

`CAP_NET_RAW` is needed for packet capture and `CAP_NET_ADMIN` for iptables.
With `"DryRun": true` only `CAP_NET_RAW` is needed.

### Docker

The container has to share the host network namespace, otherwise it only sees
and blocks its own traffic:

```sh
docker build -t geoblock .
docker run -d --name geoblock \
  --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v /etc/geoblock/config.json:/etc/geoblock/config.json:ro \
  geoblock
```

`docker-compose.yml` starts Redis and geoblock together on the host network
using `config.example.json`; edit the interface name and country list first:

```sh
docker compose up -d --build
curl -s localhost:2115/metrics | grep ^geoblock_
```

Rules are added to the host's `filter` table. To remove one:
`iptables -D INPUT -s <ip> -j DROP; iptables -D OUTPUT -d <ip> -j DROP`.

## Development

```sh
go build ./...
go vet ./...
go test -race ./...
```

The tests do not need root, libpcap devices, Redis or network access: Redis is
replaced by miniredis, the API by `httptest.Server`, and iptables by a fake.
CI runs the same commands on every push (`.github/workflows/ci.yml`).

## Limitations

- IPv4 only. IPv6 traffic is not captured or blocked.
- The ip-api.com free tier is HTTP only (no TLS) and allows 45 requests per
  minute, so a burst of new addresses takes a while to resolve. Until an
  address is resolved its traffic is counted as `unknown` and it is not
  blocked: the first packets from a blocked country get through.
- Blocking uses local iptables INPUT/OUTPUT rules on the machine running
  geoblock. It does not protect other hosts and does not integrate with an
  external firewall or router. Forwarded traffic is ignored.
- Rules are never removed automatically, and the in-memory blocked set is
  rebuilt lazily after a restart.
- Packets dropped by the OUTPUT rules are not seen by the capture and are
  therefore not counted.
- The BPF filter is built from the Redis and API addresses resolved at startup;
  if their IPs change later, that traffic is captured again (harmless, but
  counted).
- Country data is only as accurate as ip-api's database.
