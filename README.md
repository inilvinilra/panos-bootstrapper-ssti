# CVE Pending: Unauthenticated SSTI to RCE in panos-bootstrapper

| Field | Value |
|-------|-------|
| Project | [`PaloAltoNetworks/panos-bootstrapper`](https://github.com/PaloAltoNetworks/panos-bootstrapper) |
| Vulnerability | Server-Side Template Injection (CWE-1336) to Remote Code Execution |
| CVSS v3.1 | **9.8 Critical** (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |
| Authentication | None required |
| Repository status | Archived 2026-04-07, no fix available |
| CVE | Pending ([GHSA request](https://github.com/github/advisory-database/issues/10120)) |
| Reporter | Daghlar Mammadov |

## Contents

- [`disclosure/writeup-public.md`](disclosure/writeup-public.md) — full technical writeup with root cause, route inventory, PoC, and remediation
- [`poc/exploit.py`](poc/exploit.py) — Python 3 PoC (stdlib only, 4 payload variants)
- [`correspondence/psirt-thread.md`](correspondence/psirt-thread.md) — vendor coordination timeline
- [`original/REPORT_as-sent_2026-06-23.md`](original/REPORT_as-sent_2026-06-23.md) — original report as delivered to PSIRT
- [`cve/GHSA-submission.md`](cve/GHSA-submission.md) — GitHub Advisory Database submission
- [`cve/MITRE-CNA-LR-submission.md`](cve/MITRE-CNA-LR-submission.md) — MITRE CNA-LR form content

## Timeline

| Date | Event |
|------|-------|
| 2026-06-23 | Report delivered to `psirt@paloaltonetworks.com` |
| 2026-06-25 | PSIRT declined to triage (archived repository) |
| 2026-09-21 | 90-day coordinated-disclosure window elapsed |
| 2026-10-02 | Public disclosure, GHSA and MITRE CNA-LR submissions filed |
