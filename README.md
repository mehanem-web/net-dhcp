# NET//DHCP v3.0

**Listen-first DHCP with targeted serve & device discovery — Broman Enterprises**

Standalone Electron-based DHCP tool for field technicians. Opens in a passive
listen mode that shows every device asking for an address on the wire, then
serves leases to everyone — or to exactly the devices you pick. Identifies
vendors via the full IEEE OUI registry and provides one-click browser access
to discovered devices.

## The v3 model

- **LISTEN** (default on launch) — the engine binds UDP 67 and decodes every
  DHCP packet it hears, but answers nothing. Devices broadcasting DISCOVER
  appear in the table as **ASKING**, with the address they *would* get shown
  as a dry-run preview.
- **SERVE** — the big button answers everyone (classic mode), after an active
  scan for other DHCP servers on the wire.
- **TARGETED SERVE** — the per-row SERVE button answers *only that MAC*.
  Everything else stays read-only. This is the safe option on a network that
  already has DHCP.

Stopping serve drops back to listening — never to blindness.

## Features

- Pure Node.js RFC 2131 DHCP engine (no external dependencies beyond Electron)
- Passive listen mode — see every DHCP request on the wire before answering
- Targeted serve — answer a single MAC (or several) instead of the whole segment
- Unified live device table: ASKING → OFFERED → LEASED lifecycle, plus
  CONFLICT and WENT QUIET states, with retry counts and last-seen timers
- Dry-run preview — asking devices show the address they would be offered
- **Ping-before-offer** — candidate addresses are probed and quarantined if
  something already answers, before the OFFER ever goes out
- **Rogue DHCP detection** — passive (option-54 in overheard REQUESTs) and
  active (broadcasts a client DISCOVER and reports every server that answers);
  serve-all asks for confirmation when another server is live
- **Port-67 squatter naming** — on launch, netstat identifies what's holding
  UDP 67 (ICS shows up by name, not just "svchost")
- **Quick Start** — picks the wired adapter, derives the pool, scans, serves
- **Static-IP assist** — when the adapter has no usable address (APIPA), one
  click sets a temporary static IP via netsh, recorded and reverted on quit,
  with crash recovery on next launch
- **MAC → IP reservations** — pin a device to a fixed address (★ on the row)
- **Named profiles** — save and recall complete setting sets per job type
- **Idle auto-stop** — serving drops back to listen after N minutes with
  nothing served (default 30, configurable, 0 = off)
- **Self-test panel** — adapter, address, port 67, firewall rule, and
  other-DHCP checks in plain language
- Advanced options drawer: domain name (15), NTP (42), vendor-specific 43
  (raw hex — AP controller discovery), TFTP server (66), boot file (67, also
  written to the BOOTP file field)
- Full IEEE OUI registry (39,000+ prefixes, compiled in) with curated
  field-name overrides — "Hikvision", not "HANGZHOU HIKVISION DIGITAL…"
- Hostname capture from DHCP option 12
- DHCPDECLINE quarantine, option-54 server selection, ciaddr renewals
- Per-lease expiry countdown, per-row Revoke, Release All, lease CSV export
  (formula-injection safe), activity log export
- Config persistence; version injected from package.json
- Automatic Windows Firewall rule management (UDP 67)
- Shared NET// theme engine with 6 presets + custom color picker
- Minimize-to-tray with live mode + lease count tooltip

## Quick Start

1. Install via the NSIS installer, or run the portable exe (both in `dist\`
   after a build) — admin elevation is required for UDP 67
2. The app opens **listening** — plug into the segment and watch who asks
3. Either click **⚡ QUICK START** (auto-picks the adapter, fills settings,
   scans, serves) or pick a device row and hit **SERVE** for just that one

For development: `dev.bat`
For building installer + portable: `build.bat` (outputs to `dist\`)

## Install Path

NSIS installer defaults to `C:\Program Files\Broman Enterprises\NET-DHCP\`

## Requirements

- Windows 10/11
- Node.js 18+ (for dev/build)
- Administrator privileges (DHCP binds UDP port 67; netsh for firewall,
  static-IP assist, and port diagnostics)

## Changelog

### v3.0.4
- **ADD** Standalone **SCAN WIRE** button in the action row — runs the active DHCP-server scan on its own, with no serving and no changes to anything. Previously this was only reachable from inside Self-Test. Results show in a clean modal (each server found, or an all-clear), the button shows a live "scanning…" state during the ~6s window, and a SCAN AGAIN option re-runs it.
- **ADD** The scan now also reports how many genuine third-party devices were heard *asking* for an address during the window (op=1 client DISCOVERs that aren't our own probe), surfaced in the result modal and the summary log — free situational awareness from traffic we were already watching.
- **CHANGE** Self-Test's "scan for DHCP servers" action now shares the same result modal as the standalone button.

### v3.0.3
- **FIX** Active DHCP scan was closing its listen window before slow servers replied. A packet capture proved the relay-probe technique works perfectly — a consumer router answered our relayed DISCOVER with a valid unicast OFFER to port 67 — but it took ~3.3s to do so, and the window was only 2.5s. The OFFER arrived after we'd stopped listening, producing a false "no server answered." Window widened to 6s, and both scan triggers now show a "scanning…" hint so the longer wait doesn't read as a hang. (The relay channel is the reliable one; the port-68 client channel remains best-effort, since Windows' DHCP Client service intercepts broadcast OFFERs to port 68 before our socket sees them — but it's no longer needed.)

### v3.0.2
- **DIAG** Active scan is now fully instrumented. It logs each probe send and its OS-level result, every packet seen on ports 67 and 68 during the 2.5s window (source, op, transaction ID, whether it matched our probe), a firewall-rule confirmation, and an end-of-window tally. This turns a silent "no answer" into a diagnosis: replies arriving but filtered (matched > 0, none reported) points at our matching logic; nothing arriving at all (rx = 0) points at the router ignoring the probe, a firewall drop, or a failed send. Press SCAN, then copy the LOG.

### v3.0.1
- **FIX** Active DHCP scan rebuilt as dual-channel. Primary path now probes as a **relay agent** — DISCOVER with `giaddr` set to our adapter IP (hops=1), so RFC-compliant servers reply **unicast to port 67**, straight into the listener we already hold. This sidesteps both real-world failure modes of the old scan: the Windows DHCP Client service sharing port 68 and eating replies, and consumer routers that ignore the broadcast flag and unicast OFFERs to a fake MAC that can't receive them. The classic client-style probe on port 68 stays as a best-effort second channel.
- **FIX** Probe self-echo suppressed by transaction ID — the scan's own broadcast no longer risks appearing in the device table as a phantom ASKING row.
- **ADD** Scan results feed the passive foreign-server list, so Self-Test reflects the most recent scan.
- **ADD** When a scan comes back empty, the log notes any channel that had to be skipped (no usable IP / port 68 busy) so an all-clear can be judged honestly.

### v3.0.0 — the listen-first release
- **ADD** Listen mode — app opens passively decoding all DHCP traffic on UDP 67;
  the engine has four states (off / listen / serve-all / serve-targeted) on one
  persistent socket, and stopping serve returns to listen
- **ADD** Targeted serve — per-row SERVE answers only that MAC; multiple targets
  supported; big button shows and stops the whole set
- **ADD** Unified device table replacing the lease list — STATUS / IP / MAC /
  VENDOR / HOSTNAME / ACTIVITY / ACTIONS with full lifecycle states, asking rows
  pinned on top, dry-run "would offer" preview, live ago/expiry tickers
- **ADD** Ping-before-offer conflict probe with 30s result cache and per-session
  quarantine; REQUESTs for unverified addresses are probed before ACK, NAK on hit
- **ADD** Active rogue-DHCP scan (client DISCOVER from port 68, fake
  locally-administered MAC, 2.5s collection window) — gates serve-all behind a
  confirmation when another server answers; graceful fallback when port 68 is
  owned by the Windows DHCP Client service
- **ADD** Passive rogue detection — overheard option-54 server identifiers that
  aren't ours raise a toast and mark the device row
- **ADD** Port-67 squatter naming at launch via netstat→tasklist (ICS detected
  as "Windows Internet Connection Sharing", not just svchost)
- **ADD** Quick Start — wired-adapter preference, auto-derived config, rogue
  scan, serve, one click
- **ADD** Static-IP assist — sets the adapter to a free static base
  (192.168.100.1/24 first choice) via netsh when no usable address exists;
  previous state recorded in config, reverted on quit, crash-recovery prompt
  on next launch
- **ADD** MAC→IP reservations, enforced in candidate selection (NAK steers
  devices holding the wrong address back through DISCOVER); inline ★ editor
  on every row; reservations excluded from the dynamic pool
- **ADD** Named config profiles (save / load / delete)
- **ADD** Idle auto-stop — serving with nothing served for N minutes drops to
  listen (default 30, 0 disables)
- **ADD** Self-test diagnostics panel + on-demand DHCP scan
- **ADD** Advanced options drawer: 15 / 42 / 43 (hex) / 66 / 67 (+ BOOTP file
  field) with validation
- **ADD** Full IEEE OUI registry compiled to assets/oui.json (39,227 prefixes)
  with curated short-name overrides layered on top
- **ADD** Window widened 720 → 1100 for the seven-column table
- **FIX** Hardcoded v2.0 titlebar label replaced (static fallback now matches,
  runtime still injects from package.json)
- **HARDEN** Pool candidates always exclude network and broadcast addresses
  and the configured DNS; gateway validated on-subnet
- **HARDEN** Adapter names sanitized before any netsh invocation
- **CHORE** START.bat removed (installer / dev.bat / build.bat are the paths in)
- **CHORE** Lease log history raised 150 → 200 lines

### v2.1.0
- **FIX** Server IP and gateway are now excluded from the lease pool — the server can no longer hand out its own address.
- **FIX** DHCPDECLINE now quarantines the conflicting address for the session instead of recycling it straight back into the pool (prevents the offer→decline→same-offer loop).
- **FIX** Honour the server identifier (option 54) on REQUEST — if a client selected a different DHCP server, NET//DHCP releases its tentative offer and stays silent instead of ACKing a request meant for another server.
- **FIX** Renewals are honoured via `ciaddr` — a server restart mid-lease no longer ACKs an address different from the one the client already holds.
- **HARDEN** Cross-subnet warning on start: if another adapter is connected on a different subnet, the UI now warns that the server answers DHCP on all connected networks (binds 0.0.0.0).
- **HARDEN** CSV export neutralises spreadsheet formula injection from device-supplied hostnames (leading = + - @ prefixed with ').
- **HARDEN** `esc()` now also escapes the single quote; `open-browser` validates the IP before launching.
- **CHORE** Removed dead `activeAdapter` state.

### v2.0.0
- **ADD** Gateway config field — configurable DHCP option 3 (previously hardcoded to server IP)
- **ADD** DNS config field — configurable DHCP option 6 (omitted when blank; previously hardcoded to server IP)
- **ADD** Per-row Revoke button — remove individual leases without Release All
- **ADD** Config persistence — adapter, pool, gateway, DNS, lease time saved to %APPDATA% and restored on launch
- **ADD** Lease CSV export — copies IP, MAC, vendor, hostname, expiry to clipboard
- **ADD** Log export — copies full activity log to clipboard
- **ADD** Dynamic tray tooltip — shows "3 leases · serving" or "stopped"
- **ADD** Tray right-click menu shows version and live lease count
- **ADD** Version injected from package.json — titlebar auto-syncs, no manual edit needed
- **ADD** Expanded OUI table — 75+ vendor prefixes (was 15): added Verkada, Honeywell, Avigilon, Meraki, Aruba, TP-Link, Netgear, Ruckus, Juniper, Fortinet, FLIR, Panasonic, HID Global, Raspberry Pi, and more
- **FIX** DNS option no longer hardcoded to server IP — only sent when explicitly configured
- **FIX** Gateway validated as optional IP (blank = defaults to server IP)
- **FIX** Window height increased to 960px to accommodate new config fields

### v1.4.2
- FIX DHCP option parser buffer overread on malformed packets
- FIX XSS via hostname (option 12) in lease table — all dynamic values now escaped
- FIX Subnet validation now mask-aware (was /16 hardcoded)
- FIX Subnet mask validated as contiguous
- FIX Gateway defaults explicitly to server IP
- FIX Lease duration clamped server-side 30s–24h
- FIX Hostname sanitized to printable ASCII
- ADD DHCPDECLINE (type 4) handling
- ADD Option 50 (Requested IP) honored
- FIX IPC listener leak on renderer reload (safeOn guard)
- FIX build.bat — removed pause, added exit /b 0
- FIX NSIS install path set correctly
- FIX appId corrected to `net-dhcp`
- ADD README.md

### v1.4.1
- Initial audit baseline
