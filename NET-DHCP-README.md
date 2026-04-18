# NET//DHCP — v2.0
**Broman Enterprises**

A standalone DHCP server for Windows field technicians. Plug into a switch or connect directly to a device, hand out IP leases, identify vendors, and open device web interfaces — all from a single lightweight app.

**Requires Windows 10 / 11 — Administrator privileges required (DHCP binds UDP port 67)**

---

## Quick Start

1. Run the installer and launch NET//DHCP
2. Select a network adapter from the dropdown
3. Adjust pool range, lease duration, gateway, and DNS if needed
4. Click **⚡ START DHCP SERVER**

---

## Features

**DHCP Server**
- Pure RFC 2131 DHCP server — no external dependencies
- Configurable IP pool range, lease duration, gateway, and DNS
- Live adapter polling with link-up / link-down detection
- Automatic Windows Firewall rule management for UDP port 67
- Honors Option 50 (Requested IP) for INIT-REBOOT clients
- DHCPDECLINE handling for IP conflict resolution
- Hostname capture from DHCP option 12

**Lease Table**
- Live per-lease expiry countdown
- Per-row **OPEN** button — launches device web UI in browser
- Per-row **REVOKE** — remove individual leases instantly
- **RELEASE ALL** — clears all active leases
- **Export CSV** — copies IP, MAC, vendor, hostname, and expiry to clipboard

**Vendor Identification**
- OUI lookup covering 75+ prefixes — Axis, Hikvision, Dahua, Hanwha, Bosch, Pelco, Verkada, Honeywell, Avigilon, Ubiquiti, Cisco, Meraki, Aruba, TP-Link, Netgear, and more

**Activity Log**
- Full server event log with export to clipboard

**Config Persistence**
- Adapter, pool range, lease time, gateway, and DNS saved across sessions

**Tray**
- Minimize to tray with live lease count and server state in tooltip
- Right-click tray menu shows version and live lease count

---

## Changelog

### v2.0
- Added configurable gateway (DHCP option 3) and DNS (DHCP option 6) fields
- Added per-row Revoke button
- Added config persistence — all settings saved and restored on launch
- Added lease CSV export and activity log export
- Added dynamic tray tooltip and right-click tray menu
- Expanded OUI vendor table to 75+ prefixes
- Fixed DNS no longer hardcoded to server IP — only sent when configured
- Fixed gateway validation (blank defaults to server IP)

### v1.4.2
- Fixed DHCP option parser buffer overread on malformed packets
- Fixed XSS via hostname (option 12) in lease table
- Fixed subnet validation and mask handling
- Added DHCPDECLINE and Option 50 support

---

© 2026 Broman Enterprises
