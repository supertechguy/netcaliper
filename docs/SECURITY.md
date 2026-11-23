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
- Web UI/API: loopback only. Remote browser access (login with argon2id + TLS on the mgmt interface)
  is deferred to Phase 4, next to cloud enrollment; until then remote use is VNC (below) or SSH.
- Remote view/control (opt-in, `install.sh --vnc`): `wayvnc` attached to the kiosk's cage session,
  running as `ncal-kiosk` (no capabilities). Listens on :5900 in the **root namespace only**, so it is
  reachable from the management network and never from a network under test. Authentication is
  mandatory, and only encrypted security types are offered: VeNCrypt (TLS, self-signed cert generated
  on the device) and RSA-AES; no "None", no legacy VNC-password type. The password is generated on the
  device (`/etc/netcaliper/wayvnc/config`, `root:ncal-kiosk 0640`) and never leaves it unless you read
  it. A VNC user has exactly the powers of someone at the keyboard: active tests still need an
  engagement + on-screen confirmation, and are audit-logged.
- Test-plane placement: core asks the helper to move test-role links/phys into `ncal-test` by MAC; the
  helper resolves MAC→ifname itself, refuses to move the only default-route interface, and every move
  is written to the hash-chained audit log.

## Cloud
- Device tokens: 32 random bytes, stored as SHA-256, revocable. Enrollment codes: one-time, 15 min.
- Dashboard/admin behind Cloudflare Access **and** in-Worker JWT validation; `workers.dev` disabled.
- Raw artifacts (pcaps, raw scan output) never leave the device.

## Reporting
Report vulnerabilities privately via GitHub security advisories on this repository.
