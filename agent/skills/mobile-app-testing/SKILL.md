---
name: mobile-app-testing
description: Static and dynamic security testing of Android (APK/AAB) and iOS (IPA) applications
origin: RedteamOpencode
---

# Mobile App Testing (Android/iOS)

## When to Activate

- Target ships a native or hybrid mobile app (APK, AAB, IPA) alongside or instead of a web frontend
- Mobile app talks to the same backend API surface already under test — app internals reveal hidden endpoints, hardcoded secrets, or weaker auth
- Certificate pinning, root/jailbreak detection, or client-side integrity checks are blocking proxy-based testing of the app's traffic

## Tools

- `apktool`, `jadx`, `dex2jar` — Android static decompilation
- `apksigner`, `unzip` — package inspection and resigning
- `frida`, `objection` — dynamic instrumentation, pinning/root-detection bypass
- `mitmproxy`/Burp — intercept app traffic once pinning is bypassed
- `plutil`, `otool`, `class-dump`, `ipainstaller` — iOS IPA inspection (macOS/jailbroken device or emulator)
- `adb` — Android device/emulator control, logcat, app data pull
- `mobsf` (MobSF) — automated static/dynamic baseline scan if available

## Methodology

### 1. Static Analysis — Android

- [ ] Unpack: `apktool d app.apk -o out/` and `jadx app.apk -d src/` for readable Java/Kotlin
- [ ] Read `AndroidManifest.xml`: exported activities/services/receivers/providers, `android:debuggable`, `android:allowBackup`, permissions requested
- [ ] Grep decompiled source for hardcoded secrets: API keys, base URLs, JWT signing keys, cloud credentials
- [ ] Check `network_security_config.xml` for cleartext traffic permission and pinning config
- [ ] Inspect local storage: SharedPreferences XML, SQLite DBs, Realm files under `/data/data/<pkg>/` for unencrypted PII, tokens, or credentials
- [ ] Check for insecure crypto: ECB mode, hardcoded IVs/keys, weak PRNGs, custom "obfuscation" standing in for encryption

### 2. Static Analysis — iOS

- [ ] Extract IPA (`unzip app.ipa`), inspect `Info.plist` for `NSAppTransportSecurity` exceptions (arbitrary loads, disabled ATS)
- [ ] `class-dump`/`otool -L` the binary for linked frameworks, embedded URLs, and hardcoded keys
- [ ] Check `Info.plist` URL schemes and Universal Links / Associated Domains config for hijackable custom schemes
- [ ] Inspect Keychain usage class (`kSecAttrAccessible*`) — data accessible without device unlock is a finding
- [ ] Check for jailbreak-detection and anti-debugging logic (candidates for Frida bypass in dynamic phase)
- [ ] Universal Links validation bypass: fetch `https://<domain>/.well-known/apple-app-site-association` (AASA) and check for overly broad `paths` entries (`*` or unscoped wildcards) that let any URL path route into the app; also check whether the app validates the *full* incoming URL after the OS hands it off, or trusts the path blindly — a missing second validation step lets an attacker craft a Universal Link that passes AASA routing but reaches a sensitive deep-link handler (password reset, OAuth callback, deep auth token consumption) with attacker-controlled parameters
- [ ] Custom URL scheme hijack: enumerate `CFBundleURLTypes` in `Info.plist`; if the same scheme is claimed by multiple installed apps, iOS's first-come-first-served resolution lets a malicious app register the same scheme and intercept OAuth/SSO redirect callbacks or password-reset tokens intended for the legitimate app
- [ ] App Transport Security (ATS) exception abuse: grep `Info.plist` for `NSExceptionDomains`, `NSExceptionAllowsInsecureHTTPLoads`, `NSExceptionMinimumTLSVersion`, and `NSExceptionRequiresForwardSecrecy` set to permissive values per-domain — a narrowly-scoped exception for a third-party SDK domain is lower risk than a blanket `NSAllowsArbitraryLoads: true`, but both should be flagged with the exact domain list and whether in-scope traffic actually flows through the excepted domain
- [ ] Keychain access-group / sharing misconfig: check `keychain-access-groups` in the app's entitlements — an overly broad or mistyped team-prefixed group (or a group shared with a debug/staging build still installed on the same device) lets a co-installed app in the same access group read Keychain items it shouldn't; also check whether `kSecAttrSynchronizable` (iCloud Keychain sync) is enabled for sensitive items, which extends exposure across the user's other devices

### 3. Dynamic Instrumentation & Pinning Bypass

- [ ] Install app on rooted/jailbroken device or emulator; attach Frida (`frida -U -f <pkg> -l bypass.js --no-pause`)
- [ ] Use `objection explore` for quick pinning/root-detection bypass (`android sslpinning disable`, `ios sslpinning disable`) before scripting custom bypasses
- [ ] Once pinning is bypassed, route traffic through mitmproxy/Burp CA cert installed on the device — reuse `proxy_addon.py` ingestion so intercepted API calls land in `cases.db` for the vulnerability-analyst to triage like any other endpoint
- [ ] Pull and inspect runtime storage: `adb pull /data/data/<pkg>/shared_prefs`, `adb backup` (if allowed), Keychain dump via `objection`
- [ ] Test deep links / intent filters: `adb shell am start -W -a android.intent.action.VIEW -d "myapp://reset?token=..."` for auth bypass, injection, or unauthorized navigation
- [ ] Test WebViews embedded in the app for JS bridge exposure (`addJavascriptInterface`), file:// access, and mixed-content loading
- [ ] WebView JS-bridge RCE chain: if `addJavascriptInterface`/`WKScriptMessageHandler` exposes a native method that accepts a URL/HTML/file path and the WebView also allows navigation to attacker-controlled content (open redirect in an in-app browser, unvalidated `loadUrl()` call, or a `postMessage` handler with no origin check), chain them — attacker page calls the exposed JS interface to reach a native method (file read/write, `Runtime.exec`, `Intent` launch, `loadDataWithBaseURL` for a UXSS-to-native pivot) that a normal web page could never reach; on Android < 4.2 any exposed `addJavascriptInterface` is reflection-RCE by design (`interface.getClass().forName(...)`) regardless of app logic
- [ ] Check WebView config flags: `setJavaScriptEnabled(true)` + `setAllowFileAccessFromFileURLs(true)`/`setAllowUniversalAccessFromFileURLs(true)` together let a loaded `file://` page (or one reached via a path-traversal in a "view local HTML" feature) read arbitrary app-private files via `XMLHttpRequest`/`fetch` and exfiltrate them through the JS bridge

### 3a. Frida Bypass Script Patterns

- [ ] Universal Android SSL pinning bypass — hook `TrustManagerImpl.verifyChain`, `OkHttpClient.CertificatePinner.check`, and `X509TrustManager.checkServerTrusted` simultaneously so the target's specific pinning library doesn't matter:
  ```js
  Java.perform(function () {
    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use('okhttp3.CertificatePinner');
    ApiClient.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
      console.log('[+] CertificatePinner.check() bypassed for: ' + a);
      return;
    };
  });
  ```
- [ ] Root-detection bypass — hook common check functions (`RootBeer.isRooted`, `File.exists` for `su`/`busybox`/Magisk paths, `Runtime.exec("su")`) and force a `false`/exception-swallowed return; layer with `frida-multiple-unpinning` / `objection`'s `android root disable` as a first pass before writing custom hooks
- [ ] Native (JNI/`.so`) pinning or integrity checks — pinning implemented in native code survives Java-layer bypasses; use `Interceptor.attach` on the exported native function (found via `frida-trace -i "*ssl*"` or `nm -D libnative.so`) to patch the return value at the assembly level
- [ ] Anti-Frida / anti-debug detection — hook `ptrace`, `/proc/self/status` `TracerPid` reads, and `frida-server` port/process-name scans; run under a renamed `frida-server` binary or `frida-gadget` embedded in the repacked APK when the app kills itself on detection
- [ ] iOS pinning/jailbreak bypass — use `objection ios sslpinning disable` first; for custom Swift/Obj-C pinning, hook `SecTrustEvaluate`/`SecTrustEvaluateWithError` and force a success result; jailbreak-detection bypass typically hooks `stat`/`fork`/`system` calls checking for Cydia, `/bin/bash`, or writable system paths

### 4. Backend Surface Discovery via the App

- [ ] Diff mobile API calls against the web app's API surface — mobile-only endpoints are frequently under-tested and under-protected
- [ ] Check whether mobile API auth differs from web (e.g., static API key instead of session/JWT) — treat as its own auth-bypass surface, see `auth-bypass` and `jwt-testing`
- [ ] Test certificate/public-key pinning bypass persistence across app restarts and OS-level cert trust changes

### 5. Platform-Specific Abuse

- [ ] Android: exported component abuse — launch exported Activities/Services/Receivers/Providers directly via `adb` without going through the app's intended flow
- [ ] Android: tapjacking / overlay attacks if the app displays sensitive input over other apps
- [ ] iOS: Keychain data persistence after app uninstall (should be wiped, often isn't)
- [ ] Both: biometric auth bypass — check whether biometric prompt gates a local-only check versus a server-verified challenge; if local-only, hook the success callback directly with Frida to skip the prompt entirely

### 6. IPC & Content-Provider Abuse (Android)

- [ ] Enumerate every exported `ContentProvider` in the manifest (`android:exported="true"` or implicit export on old `targetSdkVersion` < 17); query them directly without going through the app: `adb shell content query --uri content://<authority>/<path>`
- [ ] Test exported ContentProviders for SQL injection via the `selection`/`sortOrder`/`projection` parameters of `query()` — these frequently concatenate raw strings into the backing SQLite query
- [ ] Test exported ContentProviders for path traversal via `openFile()`/`openAssetFile()` — request `content://<authority>/../../../data/data/<pkg>/shared_prefs/secrets.xml`
- [ ] Enumerate exported `BroadcastReceiver`s; send crafted broadcasts via `adb shell am broadcast -a <action> --es <extra> <value>` to trigger unauthenticated state changes (login, unlock, config change)
- [ ] Check for sticky broadcasts and broadcasts sent without a `LocalBroadcastManager`/signature-permission — any app on the device can intercept them and harvest tokens/PII in transit
- [ ] Enumerate exported `Service`s (`adb shell dumpsys package <pkg> | grep -A2 Service`); bind or start them directly (`adb shell am startservice`) to reach functionality that skips the UI's authorization checks
- [ ] Check Binder-based IPC (AIDL interfaces) for missing caller-UID/permission checks on privileged methods
- [ ] Check clipboard usage — copying OTPs/tokens/passwords to the system clipboard is readable by any other foreground app on Android < 13
- [ ] Check `FLAG_SECURE` usage on sensitive screens (missing it lets screenshots/screen-recording capture PII, OTPs, card numbers) and verify it isn't trivially bypassed via accessibility-service screen readers
- [ ] Pull and grep `adb logcat` during login/payment/OTP flows for leaked tokens, PANs, or stack traces containing secrets — verbose logging left in production builds is a common leak vector

### 7. React Native / Flutter / Hybrid Framework Analysis

- [ ] Detect the framework: React Native ships `assets/index.android.bundle` (Android) or `main.jsbundle` (iOS); Flutter ships `libflutter.so` + `libapp.so` (AOT-compiled Dart) with no readable bundle; Cordova/Ionic ship a `www/` directory of plain HTML/JS/CSS inside the package
- [ ] React Native: extract and beautify the JS bundle (`npx react-native-decompiler` or manual `js-beautify` on the unpacked bundle) — business logic, API endpoints, hardcoded keys, and auth logic frequently live entirely in this bundle since RN apps ship most of the app as JS, not native code
- [ ] React Native + Hermes: if the bundle is Hermes bytecode (`.hbc`, magic bytes `c6 1f bc 03`) rather than plain JS, static grep fails silently — disassemble with `hermes-dec`/`hbctool` before searching for secrets or API logic; do not conclude "no findings" from a Hermes bundle without first confirming it was actually decompiled
- [ ] React Native bridge abuse: enumerate native modules exposed to JS (`@ReactMethod` on Android, `RCT_EXPORT_METHOD` on iOS) — same class of risk as a WebView JS bridge; a native method reachable from JS with insufficient input validation is reachable from any JS that gets injected into the bundle (compromised CDN-delivered bundle update, man-in-the-middled `codepush`/OTA update channel)
- [ ] Check for CodePush/OTA JS-bundle update mechanisms without signature verification — an attacker who can MITM or compromise the update CDN can push arbitrary JS that runs with full bridge access, a persistent RCE-equivalent primitive; verify update payloads are signed and the signature is checked before execution, not just checksummed
- [ ] Flutter: `libapp.so` is AOT Dart, not a standard ELF-import-table binary — string/secret extraction still works via plain `strings`/`grep`, but control-flow analysis requires a Dart-aware disassembler (`blutter`, `reFlutter`) since function boundaries aren't in standard symbol tables; note that Flutter's own platform-channel calls (`MethodChannel`) are the JS-bridge equivalent
- [ ] Flutter method-channel abuse: enumerate `MethodChannel`/`EventChannel` names (grep decompiled Dart snapshot or `libapp.so` strings for channel name literals) and the native-side handler for each — a channel handler that trusts the Dart-side argument without validation is invokable from any code that can reach the Flutter engine's channel dispatch, including a compromised plugin or (on rooted/jailbroken devices) direct platform-channel injection via Frida
- [ ] Flutter disables standard TLS-pinning-bypass tooling (objection/Frida hooks targeting Java/ObjC TLS classes) because networking goes through Dart's own `dart:io` HttpClient with a statically-linked BoringSSL — pin bypass requires hooking the Dart VM's SSL verification function directly (`SSL_VERIFY_NONE` patch via Frida on `libflutter.so`, e.g. `Interceptor.replace` on the exported `ssl_verify_result_t` callback) rather than the usual Java `TrustManager` hooks
- [ ] Cordova/Ionic/hybrid: the entire app is a `www/` bundle of HTML/JS/CSS running in a WebView — treat it as a full web app for `xss-testing`/injection purposes, but note that any XSS here has native-bridge reach (Cordova plugins expose camera, filesystem, contacts, geolocation to JS) making a "mere" XSS a full device-capability compromise; check `config.xml` `<allow-navigation>`/`<allow-intent>` origin whitelists for overly broad wildcards that let a compromised ad/analytics iframe reach the native bridge

## What to Record

- App package/bundle ID, version, and platform
- Secrets or credentials found in binary/decompiled source (file + line/offset)
- Insecure storage locations and what sensitive data they contain
- Pinning/root-detection bypass method used (needed to reproduce)
- Any backend endpoint reachable only from the mobile client, with its auth mechanism
- Exported component or deep-link abuse PoC (exact `adb`/`frida` command)
- Severity and remediation: server-side validation, proper Keychain/Keystore usage, pinning implementation, remove hardcoded secrets
