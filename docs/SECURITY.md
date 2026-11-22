# Security

## Rules (non-negotiable)
- **Passive** tests are always allowed: link, LLDP/CDP, DHCP, DNS, gateway, Wi-Fi/BLE/RF scanning,
  ARP discovery on the local segment.
- **Active** tests — nmap beyond host discovery, NSE, vulnerability scans, segmentation probes, SNMP
  queries of other devices — require an **Engagement** (name, authorized CIDRs/SSIDs, exclusions,
  authorizer, start/expiry). The module runner enforces it; modules cannot bypass it. Hostname targets
  are resolved and *every* address must be in scope.
- Every active action (allowed or denied) is written to a **hash-chained audit log** that syncs to the
  cloud with top priority.
- **Out of scope:** credential brute-forcing, deauth/disassociation, attack packet injection,
  keystroke injection (MouseJack is detection only; payloads are discarded in the driver), jamming,
  anything that disrupts rather than measures.

## Threat model (device)
The box is plugged into untrusted networks.
- Test interfaces live in the `ncal-test` netns: the UI/API and management uplink are unreachable from them.
- nftables in `ncal-test`: input default-drop except established/related, DHCP/DHCPv6 client, essential
  ICMP/ICMPv6; reflector/iperf ports only while explicitly enabled (with TTL). No forwarding.
- Services run as `netcaliper` with only `CAP_NET_RAW`/`CAP_NET_ADMIN`; the kiosk browser runs as a
  separate user with no capabilities.
- Root is confined to `netcaliper-helper`: allowlisted, schema-validated actions, peer-credential
  checked, no shell. Changes to the helper get a dedicated review.
- Web UI: loopback only until Phase 1 adds login (argon2id) + TLS for mgmt-interface access.

## Cloud
- Device tokens: 32 random bytes, stored as SHA-256, revocable. Enrollment codes: one-time, 15 min.
- Dashboard/admin behind Cloudflare Access **and** in-Worker JWT validation; `workers.dev` disabled.
- Raw artifacts (pcaps, raw scan output) never leave the device.

## Reporting
Report vulnerabilities privately via GitHub security advisories on this repository.
