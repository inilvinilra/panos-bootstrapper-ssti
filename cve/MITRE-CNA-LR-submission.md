# MITRE CNA-LR CVE ID request

Form:         https://mitre.github.io/mitre-cve-roles/cve-id-request
Policy:       https://mitre.github.io/mitre-cve-roles/CNA-LR/
Legacy form:  https://cveform-legacy.mitre.org  (fallback)

Precondition per CNA-LR policy: "essential details are publicly disclosed."
Publish the writeup first, then paste the public URL into the References
field below before submitting.

---

## Field map (ready to paste)

> If the refreshed May 2026 form renames or reorders fields, the content
> below still maps one-to-one; this draft follows the legacy field set.

### Request type

Request a CVE ID.

### Number of vulnerabilities being reported

1

### Vendor of the product(s) or project(s)

Palo Alto Networks

### Affected product(s)/code base

panos-bootstrapper (open-source utility; GitHub-hosted; not distributed via
PyPI). Repository: https://github.com/PaloAltoNetworks/panos-bootstrapper.

### Affected version(s)

All historical versions from the introduction of the `/import_template`,
`/update_template` and `/render_template` routes through the final commit
`8128161a2cc1f4236274ed9cb2281c873734d673` on 2026-04-07, at which point the
repository was archived (read-only). No fixed version exists.

### Affected component(s)

- Flask route handlers: `/import_template`, `/update_template`,
  `/render_template` in `bootstrapper/bootstrapper.py`.
- Template rendering sink: `compile_template()` in
  `bootstrapper/lib/bootstrapper_utils.py`, calling Flask's
  `render_template_string()` with a non-sandboxed Jinja2 environment.

### Attack vector(s)

Two unauthenticated HTTP POST requests from a network-adjacent attacker:
one to `/import_template` (or `/update_template`) storing a Jinja2 payload,
one to `/render_template` triggering execution. Alternatively, overwriting
an existing template with `/update_template` lets a subsequent legitimate
render by `/generate_bootstrap_package` trigger the same execution.

### Impact

Remote code execution as the service account on the host running
`panos-bootstrapper`. The service by design handles PAN-OS firewall
bootstrap material (init-cfg, bootstrap.xml, device license and
authentication codes, cloud storage credentials), so host compromise also
exposes that material.

### Attack type

Remote; no authentication required.

### Discoverer

Daghlar Mammadov (`<daghlarmammadov@gmail.com>`)

### Has the vendor confirmed or acknowledged the vulnerability?

Yes, acknowledged, declined to triage. On 2026-06-25, Palo Alto Networks
PSIRT (handler: `mivaldi@paloaltonetworks.com`) replied verbatim:
"`panos-bootstrapper` is an archived repository that is no longer actively
maintained. As such, this report will not be triaged further. Users of this
tool should avoid exposing the API to untrusted networks or discontinue use
entirely." PSIRT therefore accepted the characterization of the bug and
publicly recommended mitigations without assigning a CVE or publishing an
advisory; this is why MITRE CNA-LR is being asked to assign one.

### Suggested description

Unauthenticated server-side template injection in `panos-bootstrapper`
through 2026-04-07 (archived) allows remote attackers to execute arbitrary
code via the `POST /import_template` and `POST /render_template` routes
(or the equivalent `POST /update_template` route): a Jinja2 payload stored
by the first request is passed by the second to Flask's non-sandboxed
`render_template_string()`. No authentication, session, or CSRF protection
is enforced on any route. The required-variables check in
`compile_template()` relies on `jinja2.meta.find_undeclared_variables()`,
which does not list Jinja2 built-in globals (`cycler`, `lipsum`,
`namespace`, `joiner`), so payloads composed of those globals bypass the
check unconditionally.

### CWE(s)

- CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine
- CWE-94  Improper Control of Generation of Code ('Code Injection')
- CWE-306 Missing Authentication for Critical Function

### Reference(s)

- Source repository (archived): https://github.com/PaloAltoNetworks/panos-bootstrapper
- Affected handlers on commit `8128161a`:
  - https://github.com/PaloAltoNetworks/panos-bootstrapper/blob/8128161a2cc1f4236274ed9cb2281c873734d673/bootstrapper/bootstrapper.py#L397-L428
  - https://github.com/PaloAltoNetworks/panos-bootstrapper/blob/8128161a2cc1f4236274ed9cb2281c873734d673/bootstrapper/bootstrapper.py#L431-L459
  - https://github.com/PaloAltoNetworks/panos-bootstrapper/blob/8128161a2cc1f4236274ed9cb2281c873734d673/bootstrapper/bootstrapper.py#L515-L529
  - https://github.com/PaloAltoNetworks/panos-bootstrapper/blob/8128161a2cc1f4236274ed9cb2281c873734d673/bootstrapper/lib/bootstrapper_utils.py#L594-L608
- Public writeup (contains PoC, timeline, vendor correspondence summary):
  https://github.com/inilvinilra/panos-bootstrapper-ssti/blob/main/disclosure/writeup-public.md
- GitHub Advisory Database submission (concurrent): <INSERT_GHSA_ISSUE_URL>

### Additional information

The vendor is a CVE Numbering Authority (CNA) with scope over its own
products. The vendor has declined to assign a CVE to this issue, citing
archived-repository status. The software remains publicly distributed and
deployed; disclosure of the bug and assignment of a CVE is in the public
interest. If the MITRE TL-Root considers that this falls outside the MITRE
CNA-LR scope and should be routed to a different Root, please forward or
advise.

### Proof of concept (summary)

```bash
TARGET="http://<host>:5000"

curl -sS -X POST "$TARGET/import_template" \
  -H 'Content-Type: application/json' \
  --data-binary '{"name":"pwn","template":"{{ cycler.__init__.__globals__.os.popen(\"id\").read() }}","description":"poc","type":"bootstrap"}'

curl -sS -X POST "$TARGET/render_template" \
  -H 'Content-Type: application/json' \
  --data-binary '{"template_name":"pwn"}'
# -> uid=... gid=... groups=...
```

Full chain, alternative payloads and local Jinja2 reproduction are in the
public writeup linked under References.
