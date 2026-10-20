# Part 1 — HAProxy gateway on the VulnBank host

Run the numbered blocks **in order on the Ubuntu server**, using an account with
sudo. Paste each complete block, including its heredoc terminator. These commands
assume Ubuntu 22.04 or newer with systemd and Docker Compose v2 already installed.
Run from the server's existing `vuln-bank` repository directory; this guide and
`lab/compose.yml` must have been copied there first.

HAProxy is the gateway; a separate gateway application is unnecessary for this
stage. It listens on **127.0.0.1:8080**, since the original Compose file already
publishes port 80. The existing application stays reachable at its current ports.
This is a staged gateway: existing direct traffic does not pass through its policy.

| Source-IP policy | Destination |
| --- | --- |
| No map entry | Main bank, `127.0.0.1:5000` |
| `watch` | Decoy bank, `127.0.0.1:5080` |
| `block` | HTTP 403 at HAProxy |

The first stage covers routing, a persistent map, request IDs, and gateway logs.
It does not add LLM decisions, a policy adapter, or HTTP-to-database tracing.

Local verification: all shell blocks passed Bash syntax checks. The extracted
configuration passed HAProxy 2.8.15 validation and routing tests with temporary
HTTP upstreams, including header replacement, blocked requests staying out of
upstreams, and policy persistence across a process restart. Ubuntu package
installation, systemd integration, and the real bank upstreams still need the
server checks below. No commands have been run on your server.

## 1. Check the host and the existing main bank

If you customized the bank ports, substitute the actual ports throughout this
file before pasting. Do not start the original Compose project again if your
existing application runs under a different project name or deployment method.

```bash
pwd
test -f docker-compose.yml && test -f lab/compose.yml
cat /etc/os-release
docker compose version
docker compose -f docker-compose.yml ps
sudo ss -ltnp
curl --noproxy '*' --fail --show-error --max-time 10 http://127.0.0.1:5000/healthz
```

**Stop if the last command fails.** Start or repair the existing main bank first.
Only if the main bank has never been started in this checkout, use:

```bash
docker compose -f docker-compose.yml up -d --build
curl --noproxy '*' --fail --show-error --retry 30 --retry-all-errors --retry-delay 2 --max-time 10 http://127.0.0.1:5000/healthz
```

## 2. Start the decoy upstream

This uses the separate `vulnbank-research` Compose project and its PostgreSQL 16
volume. The main bank keeps its PostgreSQL 13 volume. Ollama is not started.
Do not run `lab.run` concurrently: it stops/recreates the decoy during benchmarks.
Use this block without exporting an alternate `LAB_WEB_PORT`.

```bash
LAB_WEB_PORT=5080 docker compose -f lab/compose.yml up -d --build db web
LAB_WEB_PORT=5080 docker compose -f lab/compose.yml ps
curl --noproxy '*' --fail --show-error --retry 30 --retry-all-errors --retry-delay 2 --max-time 10 http://127.0.0.1:5080/healthz
```

**Stop if either upstream is unhealthy.** Inspect decoy startup errors with:

```bash
docker compose -f lab/compose.yml logs --tail 100 db web
```

## 3. Install HAProxy and save the original configuration

```bash
sudo apt-get update
sudo apt-get install -y haproxy curl socat
haproxy -v

sudo bash <<'BASH'
set -euo pipefail
install -d -m 0755 /etc/haproxy/vulnbank-backups
backup="/etc/haproxy/vulnbank-backups/haproxy.cfg.$(date -u +%Y%m%dT%H%M%S%N)"
cp -a /etc/haproxy/haproxy.cfg "$backup"
printf 'Original HAProxy configuration saved to %s\n' "$backup"
printf '%s\n' "$backup" > /etc/haproxy/vulnbank-backups/last-config-backup
BASH

sudo cat /etc/haproxy/haproxy.cfg
```

If this host already uses HAProxy for another application, merge the frontend and
backends below into its configuration before proceeding. Step 4 replaces the
HAProxy configuration. Also confirm that port 8080 is free in Step 1.

## 4. Write and validate the gateway configuration

The map starts empty on first installation. Repeating this block preserves an
existing map. HAProxy uses the actual TCP source IP for policy. Client-supplied
forwarding and request-ID headers are overwritten or removed.

```bash
sudo bash <<'BASH'
set -euo pipefail
if [ ! -e /etc/haproxy/client-policy.map ]; then
    install -m 0644 /dev/null /etc/haproxy/client-policy.map
fi
candidate=$(mktemp /etc/haproxy/vulnbank-candidate.XXXXXX)
trap 'rm -f "$candidate"' EXIT
cat > "$candidate" <<'HAPROXY'
# VulnBank lab gateway — stage 1
global
    log stdout format raw local0
    user haproxy
    group haproxy
    maxconn 1024
    stats socket /run/haproxy/admin.sock mode 600 level admin
    stats timeout 10s

defaults
    log global
    mode http
    timeout connect 5s
    timeout client 60s
    timeout server 60s
    timeout http-request 10s
    timeout http-keep-alive 10s
    log-format "source=gateway client_ip=%ci request_id=%ID policy=%[var(txn.policy)] branch=%[var(txn.branch)] backend=%b server=%s status=%ST bytes=%B duration_ms=%Tt"

frontend fe_vulnbank
    bind 127.0.0.1:8080
    unique-id-format %ci:%cp_%fi:%fp_%Ts_%rt_%pid
    http-request set-header X-Request-ID %[unique-id]
    http-request del-header Forwarded
    http-request del-header X-Real-IP
    http-request set-header X-Forwarded-For %[src]
    http-request set-header X-Forwarded-Proto http
    http-request set-var(txn.policy) src,map_ip(/etc/haproxy/client-policy.map,main)
    http-request set-var(txn.branch) str(main)
    http-request set-var(txn.branch) str(decoy) if { var(txn.policy) -m str watch }
    http-request set-var(txn.branch) str(blocked) if { var(txn.policy) -m str block }
    http-request return status 403 content-type text/plain string "Blocked by gateway" if { var(txn.policy) -m str block }
    http-after-response set-header X-Request-ID %[unique-id]
    http-after-response set-header X-Lab-Route %[var(txn.branch)]
    use_backend be_decoy if { var(txn.policy) -m str watch }
    default_backend be_main

backend be_main
    option httpchk GET /healthz
    http-check expect status 200
    server main_bank 127.0.0.1:5000 check inter 3s fall 3 rise 2

backend be_decoy
    option httpchk GET /healthz
    http-check expect status 200
    server decoy_bank 127.0.0.1:5080 check inter 3s fall 3 rise 2
HAPROXY
/usr/sbin/haproxy -c -f "$candidate"
install -o root -g root -m 0644 "$candidate" /etc/haproxy/haproxy.cfg
systemctl enable haproxy
if systemctl is-active --quiet haproxy; then
    systemctl reload haproxy
else
    systemctl start haproxy
fi
systemctl --no-pager --full status haproxy
BASH
```

If validation fails, the running configuration is not replaced. If activation
fails, inspect `sudo journalctl -u haproxy -n 80 --no-pager` and use Step 8 to
restore the backup.

## 5. Verify main, watch, block, and restart persistence

The test temporarily adds two loopback source IPs, then restores your original
map even if a check fails. Real source addresses are used with `curl --interface`;
spoofed headers are not used to choose routes. Gateway health checks still reach
both applications periodically, including while a client is blocked.

```bash
sudo bash <<'BASH'
set -euo pipefail
policy=/etc/haproxy/client-policy.map
saved=$(mktemp /etc/haproxy/vulnbank-test-map.XXXXXX)
cp -p "$policy" "$saved"
cleanup() {
    cp -p "$saved" "$policy"
    /usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy
    rm -f "$saved"
}
trap cleanup EXIT

# Keep this test deterministic: start with an empty map temporarily.
printf '127.0.0.2 watch\n127.0.0.3 block\n' > "$policy"
/usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg
systemctl reload haproxy

check_route() {
    local source_ip=$1 expected_status=$2 expected_route=$3 response status
    response=$(curl --noproxy '*' --silent --show-error --retry 10 --retry-all-errors --retry-delay 1 --max-time 5 \
        --interface "$source_ip" -D - -o /dev/null \
        -H 'X-Request-ID: client-forged-id' -H 'X-Forwarded-For: 127.0.0.3' \
        -w '\n%{http_code}' http://127.0.0.1:8080/healthz)
    status=$(printf '%s\n' "$response" | tail -n 1)
    test "$status" = "$expected_status"
    printf '%s\n' "$response" | tr -d '\r' | grep -qi "^X-Lab-Route: ${expected_route}$"
    printf '%s\n' "$response" | grep -qi '^X-Request-ID:'
    if printf '%s\n' "$response" | grep -qi '^X-Request-ID: client-forged-id'; then
        echo 'FAIL: request ID was not replaced' >&2
        return 1
    fi
    printf 'PASS source=%s status=%s route=%s\n' "$source_ip" "$status" "$expected_route"
}

check_route 127.0.0.1 200 main
check_route 127.0.0.2 200 decoy
check_route 127.0.0.3 403 blocked
systemctl restart haproxy
check_route 127.0.0.2 200 decoy
check_route 127.0.0.3 403 blocked
echo 'PASS: all routes and on-disk policy persistence'
BASH

sudo journalctl -u haproxy --utc -o short-iso --since '5 minutes ago' --no-pager
```

Expected gateway records include `branch=main backend=be_main`,
`branch=decoy backend=be_decoy`, and `branch=blocked ... status=403` without a
selected upstream server. `X-Lab-Route` is a diagnostic response header for this
lab. Gateway logs appear in the systemd journal; retention follows host journald
settings. This stage does not configure a central log collector.

## 6. Open the gateway from your own computer

Run this on your **own computer**, using your existing SSH host alias:

```bash
ssh -N -L 8080:127.0.0.1:8080 vulnbank
```

If you have no `vulnbank` SSH alias, replace it with `YOUR_USER@SERVER_IP`.
Open `http://127.0.0.1:8080` in your browser. All clients using this SSH tunnel
appear at HAProxy as `127.0.0.1`; the tunnel cannot demonstrate distinct remote
client IPs. Step 5 tests source-IP routing directly on the host.

## 7. Apply a persistent manual policy later

This stage deliberately updates the file and reloads HAProxy. Runtime API map
changes alone are kept in memory and disappear after a reload/restart.
Do not edit the map during a fixed C0–C3 benchmark.

Back up and edit the map (one `IP watch` or `IP block` entry per line; remove an
entry to restore main routing). Use an IP that HAProxy actually observes. A
`127.0.0.1 block` entry also blocks your SSH-tunneled browser.

```bash
sudo cp -a /etc/haproxy/client-policy.map /etc/haproxy/vulnbank-backups/client-policy.map.before-manual-edit
sudoedit /etc/haproxy/client-policy.map
```

Example file contents; **do not paste this example as a shell command**:

```text
192.0.2.10 watch
192.0.2.20 block
```

Validate supported values and then apply. If this fails, restore the map backup
before making other configuration changes; the old in-memory map stays active.

```bash
sudo bash <<'BASH'
set -euo pipefail
awk '
    /^[[:space:]]*(#|$)/ { next }
    NF != 2 || ($2 != "watch" && $2 != "block") { bad=1 }
    { if (seen[$1]++) bad=1 }
    END { exit bad }
' /etc/haproxy/client-policy.map
/usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg
systemctl reload haproxy
BASH

# Read the active map through the local, root-only Runtime API socket.
printf 'show map /etc/haproxy/client-policy.map\n' | sudo socat - UNIX-CONNECT:/run/haproxy/admin.sock
```

To undo that manual edit:

```bash
sudo cp -a /etc/haproxy/vulnbank-backups/client-policy.map.before-manual-edit /etc/haproxy/client-policy.map
sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy
```

## 8. Roll back the gateway configuration if needed

This restores the configuration saved by Step 3. It leaves application containers
and database volumes intact. For a first-time HAProxy install, you can instead
stop the new gateway with `sudo systemctl disable --now haproxy`.

```bash
sudo bash <<'BASH'
set -euo pipefail
backup=$(cat /etc/haproxy/vulnbank-backups/last-config-backup)
/usr/sbin/haproxy -c -f "$backup"
cp -a "$backup" /etc/haproxy/haproxy.cfg
systemctl restart haproxy
BASH
```

## Next stage: making HAProxy the only ingress

Before a port-80 cutover, remove the original Docker mapping of host port 80 and
bind the main application's host port to loopback. Restrict its published DB port
as well. Then HAProxy can listen on the intended lab-facing interface and port 80.
Until that cutover, use the gateway URL above for gateway tests; the existing
direct app ports bypass HAProxy. TLS and trusted upstream proxies can be added
when the ingress address/domain is decided.

## Official references

Checked 2026-10-16:

- [Ubuntu HAProxy packages](https://packages.ubuntu.com/haproxy).
- [HAProxy 2.8 configuration manual](https://docs.haproxy.org/2.8/configuration.html):
  `map_ip`, `http-request`, `http-after-response`, health checks, IDs, and logging.
- [Runtime API persistence behavior](https://www.haproxy.com/documentation/haproxy-runtime-api/).
- [Inspect active maps with show map](https://www.haproxy.com/documentation/haproxy-runtime-api/reference/show-map/).
