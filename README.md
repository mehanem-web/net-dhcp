# NET//DHCP v2.0

**Auto DHCP lease & device discovery — Broman Enterprises**

Standalone Electron-based DHCP server for field technicians. Hands out IP leases on a selected NIC, identifies device vendors via OUI lookup, and provides one-click browser access to discovered devices.

## Features

- Pure Node.js RFC 2131 DHCP server (no external dependencies beyond Electron)
- Live adapter polling with link-up / link-down detection
- OUI vendor identification — 75+ prefixes covering Axis, Hikvision, Dahua, Hanwha, Bosch, Pelco, Verkada, Honeywell, Avigilon, Ubiquiti, Cisco, Meraki, Aruba, TP-Link, Netgear, and more
- Hostname capture from DHCP option 12
- Option 50 (Requested IP) honoring for INIT-REBOOT clients
- DHCPDECLINE handling for IP conflict resolution
- Configurable gateway and DNS server (DHCP options 3 and 6)
- Per-lease expiry countdown with per-row Revoke and Release All
- Lease table CSV export (copy to clipboard)
- Activity log export (copy to clipboard)
- Config persistence — pool range, lease time, gateway, DNS saved across sessions
- Version injected from package.json (no manual sync needed)
- Dynamic tray tooltip — shows lease count and server state
- Automatic Windows Firewall rule management (UDP 67)
- Shared NET// theme engine with 6 presets + custom color picker
- Minimize-to-tray with right-click server status

## Quick Start

1. **Double-click `START.bat`** — auto-elevates to admin, installs deps, launches
2. Select a network adapter from the dropdown
3. Adjust pool range / lease duration / gateway / DNS if needed
4. Click **⚡ START DHCP SERVER**

For development: `dev.bat`
For building installer + portable: `build.bat` (outputs to `dist/`)

## Install Path

NSIS installer defaults to `C:\Program Files\Broman Enterprises\NET-DHCP\`

## Requirements

- Windows 10/11
- Node.js 18+ (for dev/build)
- Administrator privileges (DHCP binds UDP port 67)

## Changelog

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
