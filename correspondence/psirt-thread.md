# Palo Alto Networks PSIRT — correspondence thread

Case subject: **Unauthenticated SSTI → Remote Code Execution in panos-bootstrapper (verified pre-auth PoC)**
Reporter: Daghlar Mammadov `<daghlarmammadov@gmail.com>`
PSIRT contact: `psirt@paloaltonetworks.com`

---

## 2026-06-23 06:58 — PSIRT (auto-ack)
> Thank you for contacting the Palo Alto Networks PSIRT.
> We have received your email and will respond as soon as we have completed our initial review.

## 2026-06-23 16:34 — Reporter (follow-up)
Requested confirmation on three items:
1. CVE assignment,
2. Public security advisory / release note,
3. Researcher acknowledgement under "Daghlar Mammadov".

Offered additional PoC material (source, screenshots, video) privately. Committed
to confidentiality until triage/remediation complete.

## 2026-06-23 16:58 — PSIRT (auto-ack #2, duplicate)

## 2026-06-25 00:37 — PSIRT (final decision, handler: mivaldi@paloaltonetworks.com)
> `panos-bootstrapper` is an archived repository that is no longer actively
> maintained. As such, this report will not be triaged further.
>
> Users of this tool should avoid exposing the API to untrusted networks or
> discontinue use entirely.

**Interpretation:**
- No CVE will be assigned by Palo Alto PSIRT (vendor CNA declined).
- No security advisory on security.paloaltonetworks.com.
- No researcher credit from the vendor.
- PSIRT does implicitly acknowledge the risk ("avoid exposing the API to
  untrusted networks or discontinue use entirely").

**Verified vendor-state facts (as of 2026-10-02):**
- Repo archived 2026-04-07 (read-only). Last commit "Update README.md" the same
  day, adding "THIS PROJECT IS NO LONGER MAINTAINED AND NOT IN USE!" banner.
- No GitHub Security Advisory published on the repo.
- No entry on security.paloaltonetworks.com matching `panos-bootstrapper`.
- No fix commit in the repo history.

---

## Next steps (reporter-side)
1. Request CVE via MITRE CNA of Last Resort — vendor declined, software is
   published PAN code with verified RCE.
2. Prepare public disclosure (90-day window from 2026-06-23 elapsed on
   2026-09-21).
3. Publish technical writeup on personal blog / GitHub Gist, cross-reference the
   CVE once assigned.
