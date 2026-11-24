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
- Web UI/API: loopback (kiosk) without login. Remote browsers: HTTPS-only listener on :8443 in the
  root namespace (so never reachable from a network under test), self-signed cert with its
  fingerprint shown at the device, and a session from the local admin password (scrypt, local secret
  store). No password set = remote access closed; the password can only be set or removed at the
  device. HttpOnly/Secure/SameSite=Strict session cookie, 12 h, memory only; a password change ends
  all sessions; failed logins throttled (5/address, 20 total per 5 min); logins audit-logged. A
  remote user has the same powers as someone at the keyboard (active tests still need an engagement).
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
- Test execution: core hands only PASSIVE `test-ns` modules to the agent (`module.run`); the agent
  re-validates the module, its config and that the interface exists in its namespace, and refuses
  ACTIVE modules outright, so it can't be used to bypass the engagement guard in core.
- 802.1X credentials are local only: a `0600` file in the data dir (`secrets.json`), deliberately
  outside SQLite so nothing in it can reach the sync outbox. The password is never rendered back,
  logged, or stored in results; wpa_supplicant gets it via a `0600` config in the agent's PrivateTmp
  that is deleted after the attempt, and values that could break out of that config are rejected.
- Wi-Fi: the saved network (passphrase / EAP credentials) lives in the same local `secrets.json`;
  certificates and keys for EAP-TLS (Wi-Fi and wired) in `data_dir/certs/` (0700 dir, 0600 files,
  fixed names, content checked to be PEM/DER) — neither is in SQLite, so neither can reach the sync
  outbox. Credentials are injected into the step config by core only for the saved SSID, travel to
  the agent over the local socket, go into a 0600 wpa_supplicant config in the agent's PrivateTmp,
  and are deleted when the test ends; results never contain them (tested).
- Wi-Fi tests are client-level and passive in the CyberScope sense: scanning, associating with a
  network we were given credentials for, roaming between *its* APs, and listening in monitor mode.
  Nothing transmits deauth/disassoc, injects frames, or guesses credentials. Monitor capture parses
  802.11 headers and the IEs that APs broadcast (plus the SSID in probe requests); data payloads are
  never read or kept. Results include client MAC addresses, AP associations and probed SSIDs (the
  report's purpose: who is on which AP, and locating them); like all results they sync as metadata.
- State-changing UI/API requests carrying a foreign `Origin` are refused (a page the kiosk browser
  was sent to can't drive the device).

## Cloud
- Device tokens: 32 random bytes, stored as SHA-256, revocable from the dashboard (401 stops the
  device until re-enrolled). On the device the token sits in the local secret store, never synced.
- Enrollment codes: 50 random bits (Crockford base32), shown once, stored as SHA-256, 15 min, single
  use (claimed atomically).
- Dashboard/admin behind Cloudflare Access **and** in-Worker JWT validation (RS256 against the team
  JWKS; audience, issuer, expiry checked; fails closed when unconfigured); `workers_dev` and
  `preview_urls` off; the deploy script refuses a config that differs. Device endpoints
  (`/api/v1/enroll|sync|config|health`) are the only Access bypass and authenticate by token.
- Admin state changes need `application/json` and a same-origin `Origin` (CSRF). Strict CSP, no
  inline script; device-supplied text is never inserted as HTML.
- Every record is validated server-side; ids, sizes and statement counts are bounded; the device id
  comes from the token, so a device can't write as another one.
- What syncs: runs, results (incl. client MACs and SSIDs in Wi-Fi details), findings, audit log.
  What never syncs: raw artifacts (pcaps, raw scan output), credentials, certificates, the device token.
  Cloud profiles containing credential fields are refused.

## Reporting
Report vulnerabilities privately via GitHub security advisories on this repository.
