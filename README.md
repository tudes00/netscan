# Netscan

Fast network host discovery via ICMP and ARP, written in Bash.

Scans a range of IPs in parallel, resolves hostnames, retrieves MAC addresses on local networks, and optionally exports results to CSV. Automatically switches between ARP (local) and ICMP (remote) depending on the target subnet.

![demo](demo.svg)

## Requirements

- `fping` — ICMP ping
- `arping` — ARP scanning (requires root)
- `dig` — hostname resolution
- `bc` — timeout conversion for arping
- `ip` — interface and address detection

```bash
# Debian / Ubuntu
apt install fping arping dnsutils bc iproute2
```


## Installation

```bash
git clone https://github.com/tudes00/netscan.git
cd netscan
chmod +x netscan.sh
```
If you want to use it like this `netscan` instead of `netscan.sh`:
```bash
sudo mv netscan.sh /usr/local/bin/netscan
```


## Usage

```
./netscan.sh <TARGET> [OPTIONS]
```

### Target formats

| Format | Example |
|--------|---------|
| CIDR | `192.168.1.0/24` |
| Single IP | `192.168.1.1` |
| Range | `192.168.1-10.1-20` |
| List | `192.168.1.1,192.168.1.5` |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --timeout <ms>` | `800` | Ping timeout in milliseconds |
| `-j, --max-jobs <n>` | `400` | Max parallel jobs |
| `-i, --interface <iface>` | auto | Network interface (e.g. `eth0`, `wlan0`) |
| `-r, --retry <n>` | `1` | Number of ping retries |
| `-o, --output <file>` | - | Save results to a CSV file |
| `-e, --exclude <target>` | - | Exclude IPs (same formats as TARGET, repeatable) |
| `-H, --no-hostname` | - | Skip hostname resolution |
| `--no-color` | - | Disable colored output |
| `--no-progress` | - | Disable progress bar |
| `--icmp` | - | Force ICMP mode |
| `--arp` | - | Force ARP mode (requires root) |
| `-l, --list-interfaces` | - | List available network interfaces |
| `-h, --help` | - | Show help |

---

## Examples

```bash
# Scan a full subnet
sudo ./netscan.sh 192.168.1.0/24

# Scan a range, skip hostname resolution
sudo ./netscan.sh 192.168.1.1-50 -H

# Scan with a short timeout, save results
sudo ./netscan.sh 10.0.0.0/8 -t 400 -j 300 -o results.csv

# Scan with exclusions
sudo ./netscan.sh 192.168.1.0/24 -e 192.168.1.1-10 -e 192.168.1.254

# Single external host, 3 retries
sudo ./netscan.sh 8.8.8.8 -t 1500 -r 3 --icmp
```

---

## How it works

- **Auto mode** (default): uses ARP for IPs on the local subnet, ICMP for everything else.
- **Parallel scanning**: jobs are dispatched up to `--max-jobs` simultaneously, then throttled via `wait -n`.
- **Hostname resolution**: reverse DNS via `dig -x`.

---

## Output

Live hosts are printed to stdout as they are found (not in order):

```
● 192.168.1.42 is alive - router.local - AA:BB:CC:DD:EE:FF
● 192.168.1.101 is alive - Unknown
```

If `--output` is set, results are appended to a CSV file:

```
192.168.1.42,router.local
192.168.1.101,Unknown
```

---

## Notes

- Root is required for ARP mode. Running without root falls back to ICMP automatically.
- Large ranges (e.g. `/8`) should use reduced `--max-jobs` and increased `--timeout` to avoid overwhelming the system.
