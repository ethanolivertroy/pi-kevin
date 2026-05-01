# pi-kevin

`pi-kevin` is a Pi-native extension for browsing and analyzing the CISA Known Exploited Vulnerabilities (KEV) catalog.

It replaces the old `kevs-tui` Go/Bubble Tea app with a native **Pi extension + skill** package, so KEV search, triage, remediation guidance, compliance mapping, and analytics all live directly inside Pi.

## Why this exists

The original `kevs-tui` proved out a great workflow:
- fast KEV search
- EPSS-aware prioritization
- agentic vuln assistance
- compliance and analytics workflows

KEVin Pi keeps that workflow, but makes it native to Pi instead of maintaining a separate app runtime.

## Install

### Global install

```bash
pi install https://github.com/ethanolivertroy/pi-kevin
```

### Project-local install

```bash
cd /path/to/project
pi install -l https://github.com/ethanolivertroy/pi-kevin
```

## Quick start

Open Pi, then use:

```bash
/kev
```

Useful follow-ups:

```bash
/cve CVE-2024-3400
/skill:kev-analyst
```

## Browser preview

Representative `/kev` layout:

```text
╭──────────────────────────────────────────────────────────────────────────────╮
│◆ KEVin Browser • CISA Known Exploited Vulnerabilities                       │
│[1461 KEVs] [201 ransomware] [73 overdue]                                    │
│⌕ Search: palo alto                                                          │
│Sort best • preview • ransomware                                             │
│──────────────────────────────────────────────────────────────────────────────│
│◆ Results                                    ◆ Preview                       │
│▌ CVE-2024-3400 PAN-OS command injection      CVE-2024-3400 • RANSOMWARE     │
│  Palo Alto | PAN-OS | EPSS 95% ███████████   PAN-OS • Added 2024-04-12      │
│▌ CVE-2024-0012 PAN-OS auth bypass             Summary                        │
│  Palo Alto | PAN-OS | EPSS 81% █████████░░░   Required action                │
│                                               Enter pin • Ctrl+P patch       │
│                                               Ctrl+N NVD • Ctrl+V top ref    │
│──────────────────────────────────────────────────────────────────────────────│
│type to search • ↑↓ move • PgUp/PgDn jump • Tab detail/preview               │
│Enter pin • Ctrl+P patch • Ctrl+E exploit • Ctrl+G controls • Ctrl+L related │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Workflow demo

The animation below is from the original `kevs-tui` workflow that KEVin Pi replaces. The Pi-native package keeps the same fast KEV triage flow while moving it into Pi commands, tools, and overlays.

![KEVin workflow demo](docs/kevin-workflow-demo.gif)

## What you get

### Interactive KEV browser
- `/kev` opens a Pi-native KEV browser overlay
- type to search by CVE, vendor, product, description, or CWE-like terms
- preview/detail mode for richer inspection
- safe quick actions that do not interfere with search typing

### Current CVE context
- `/cve <id>` pins a CVE as active context
- the agent can use that pinned context when you ask follow-up questions like:
  - “what should I do?”
  - “is this urgent?”
  - “map this to controls”

### KEVin analyst skill
- `kev-analyst` gives the model a remediation-first workflow
- emphasizes patch status and exploitability before broader discussion
- uses compliance mapping only when explicitly relevant

## Built-in KEVin tools

### Core KEV tools
- `search_kevs`
- `get_cve_details`
- `list_ransomware_cves`
- `list_overdue_cves`
- `get_stats`
- `check_patch_status`
- `check_exploit_availability`

### Compliance / GRC tools
- `map_cve_to_controls`
- `get_control_details`
- `list_controls`

### Analytics tools
- `find_related_cves`
- `get_vendor_risk_profile`
- `batch_analyze`
- `analyze_cwe`
- `analyze_trends`

## Commands

- `/kev` — open the KEV browser
- `/kev <query>` — open the browser with a prefilled query
- `/cve <id>` — pin the current CVE context
- `/kev-clear` — clear the pinned CVE context
- `/kev-ui auto|on|off` — control KEVin UI chrome behavior

## Browser controls

### Navigation
- type to search
- `↑/↓` move selection
- `PgUp/PgDn` jump
- `Home/End` move to top/bottom
- `Backspace` delete search
- `Ctrl+U` clear search

### Sorting and filtering
- `Ctrl+S` cycle sort mode
- `Ctrl+R` toggle ransomware-only
- `Ctrl+O` toggle overdue-only

### Modes and actions
- `Tab` toggle preview/detail mode
- `Enter` pin selected CVE
- `Ctrl+P` quick patch-status handoff
- `Ctrl+E` quick exploitability handoff
- `Ctrl+G` quick controls mapping handoff
- `Ctrl+L` quick related-CVEs handoff
- `Ctrl+N` open the selected CVE in NVD
- `Ctrl+V` open the top patch/advisory reference when available
- `Ctrl+Y` copy the best available link for the selected CVE
- `Esc` close

## UI behavior

KEVin UI is intentionally lazy by default.

In `auto` mode:
- it does **not** show chrome on startup
- it wakes up when you use `/kev`, `/cve`, or a KEVin tool
- it hides again after inactivity or when you clear the current CVE context

If you want different behavior:

```bash
/kev-ui on
/kev-ui off
/kev-ui auto
```

## Successor to `kevs-tui`

The older `kevs-tui` repository is now archived.

KEVin Pi is the actively maintained successor:
- old repo: `ethanolivertroy/kevs-tui`
- current repo: `ethanolivertroy/pi-kevin`

## Development

```bash
npm install
npm run typecheck
```

## Status

KEVin Pi is already useful and actively evolving.

Recent polish includes:
- richer detail mode with required action, notes, description, CVSS, CWEs, and top references
- safer quick-action handoffs for remediation, exploitability, controls, and related KEVs
- actionable browser links for NVD and top patch/advisory references
- a more KEVin-style browser layout inside Pi
