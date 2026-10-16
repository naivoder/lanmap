# lanmap

Map a local network from the command line. lanmap writes a single self-contained HTML report with:

- **Topology**: the uplink path (traceroute), each subnet, and its devices grouped by function
- **Segmentation plan**: a suggested VLAN per zone, plus every observed cross-zone conversation, which becomes your firewall rule list
- **Discovery warnings**: broadcast/multicast protocols (DHCP, mDNS, SSDP, NetBIOS…) that break when you split VLANs
- **Data flows**: who connects to whom, on which port, and how much
- **Address space**: every IP in each subnet, coloured by zone, with the largest free ranges
- **Services**: a matrix of open ports, with banners
- **Inventory**: a sortable, filterable host table (MAC, vendor, OS guess, role, ports)

A JSON file with the raw scan is written next to the report.

## Install

Linux, Python 3.9+, iproute2 (`ip`, `ss`). Single file; the only dependency is `rich`.

```bash
pipx install ./lanmap          # or: pip install rich && python3 lanmap.py
```

Optional extras that improve results: `nmap` or `arp-scan` (full MAC-vendor database; arp-scan is also used for discovery when root), `traceroute`.

## Use

```bash
lanmap                          # scan every attached subnet (unprivileged)
lanmap --capture 300            # + arp-scan + 5 min passive traffic capture (re-runs itself under sudo)
lanmap -t 10.0.20.0/24 -p 1-1024,3389,8080
lanmap --demo --open            # sample report, no scanning
lanmap --from-json scan.json    # re-render a saved scan
```

## How it works

| Step | Unprivileged | As root |
|---|---|---|
| Discovery | ICMP sweep + kernel ARP table (catches hosts that block ping) | + `arp-scan` |
| Identity | reverse DNS, NetBIOS name, SNMP `sysDescr` (community `public`), MAC vendor | same |
| Ports | async TCP connect scan of 85 common ports, with HTTP title/Server and SSH/FTP/SMTP banners | same |
| Flows | this host's own sockets (`ss`) | + passive capture (AF_PACKET, promiscuous) incl. ARP, 802.1Q tags |

Roles (gateway, switch/AP, server, NAS, workstation, phone, printer, VoIP, IoT, camera) come from heuristics on vendor, ports, banners and TTL. They map to zones, and each zone gets a suggested VLAN (10 infrastructure, 20 servers, 30 users, 40 printers, 50 voice, 60 IoT, 70 cameras). Treat these as a first draft.

## Getting complete flows

On a switched network, a host only sees its own traffic plus broadcast/multicast. To map every conversation, run the capture from a port that sees everything:

1. Configure a **mirror/SPAN port** on the core switch that copies the uplink (or the whole VLAN).
2. Plug the scanning machine's second NIC into it.
3. `sudo lanmap -i eth1 --capture 3600`, run during business hours. Repeat across a few days to catch backups and batch jobs.

Alternatively, export NetFlow/sFlow from the firewall or switches into a collector such as ntopng.

Only scan networks you own or are authorised to assess. Non-private ranges are refused unless you pass `--allow-public`.
