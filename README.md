# KEVin Pi

KEVin Pi is a native Pi package for browsing and analyzing the CISA Known Exploited Vulnerabilities catalog.

This package replaces the old `kevs-tui` app with a Pi-native extension + skill architecture.

## Current features

- Fast cached KEV catalog search
- Current CVE context widget
- Pretty interactive `/kev` browser overlay with split-pane preview
- `/cve <id>` to pin the current vulnerability context
- `kev-analyst` skill for remediation-focused vuln triage
- Pi tools for:
  - `search_kevs`
  - `get_cve_details`
  - `list_ransomware_cves`
  - `list_overdue_cves`
  - `get_stats`
  - `check_patch_status`
  - `check_exploit_availability`
  - `map_cve_to_controls`
  - `get_control_details`
  - `list_controls`
  - `find_related_cves`
  - `get_vendor_risk_profile`
  - `batch_analyze`
  - `analyze_cwe`
  - `analyze_trends`

## Install

```bash
pi install https://github.com/ethanolivertroy/kevin-pi
```

Or project-local:

```bash
cd /path/to/project
pi install -l https://github.com/ethanolivertroy/kevin-pi
```

## Commands

- `/kev` - open the KEV browser
- `/kev <query>` - open the KEV browser with a query
- `/cve <id>` - set the current CVE context
- `/kev-clear` - clear the current CVE context
- `/kev-ui auto|on|off` - control whether KEVin UI chrome is shown automatically, always, or never

By default, KEVin UI is now lazy:
- it does not warm cache or show chrome on startup
- it wakes up when you use `/kev`, `/cve`, or a KEVin tool
- in `auto` mode, the widget hides again after inactivity or when you clear the current CVE context

## Development

```bash
npm install
npm run typecheck
```
