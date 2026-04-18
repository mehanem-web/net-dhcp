## NET//DHCP v2.0

A standalone DHCP server for Windows field technicians. Plug into a switch, hand out IP leases, identify device vendors by MAC address, and open device web interfaces in one click.

**Requires Windows 10 / 11 — must run as Administrator**

---

### What's in it

**DHCP Server** — RFC 2131 compliant, no external dependencies. Configurable IP pool, lease duration, gateway, and DNS. Automatic Windows Firewall rule management so it just works.

**Lease Table** — Live expiry countdowns per device. Open a device's web UI directly from the table, revoke individual leases, or release everything at once. Export leases to CSV with one click.

**Vendor ID** — Identifies 75+ device vendors by MAC prefix — covers the major camera, NVR, switch, and access control manufacturers used in the field.

**Tray** — Minimize to tray with live lease count in the tooltip. Right-click for server status and version.

---

### v2.0 Changes

- Added configurable gateway and DNS fields (previously hardcoded to server IP)
- Added per-row Revoke button — remove individual leases without clearing everything
- Added config persistence — adapter, pool, gateway, DNS, and lease time saved across sessions
- Added lease CSV export and activity log export to clipboard
- Added dynamic tray tooltip and right-click tray menu with live lease count
- Expanded OUI vendor table from 15 to 75+ prefixes

---

*All data stored locally — nothing is transmitted externally.*
