# 🛡️ CipherScanner

A standalone FiveM server-side security resource that scans every installed resource for known **cipher / backdoor malware** patterns and actively hardens the server against the techniques those payloads rely on — obfuscated dynamic code, hidden HTTP exfiltration, bytecode injection, and shell execution.

<img width="1337" height="649" alt="image" src="https://github.com/user-attachments/assets/9636a01e-7b02-4d34-8b1e-eb36f7dd7d13" />


---

## 📦 Requirements

- FiveM server
- No framework required (Standalone)

---

## 📁 Installation

1. Download or clone the repository.
2. Place `zaylf4-cipherscanner` into your server's `resources` folder.
3. Add the resource to `server.cfg`:

```
ensure zaylf4-cipherscanner
```

4. Restart your server.

> Load it as early as possible in `server.cfg` (before other resources) so the runtime protections are active before anything else starts.

---

## 🚀 Usage

All commands are **server-console only**.

Run a full scan of every started resource on demand:

```
cipherscan
```

Scan a single resource by name:

```
cipherscan_res <resource>
```

Toggle debug logging at runtime without restarting:

```
cipherscan_debug on
```
```
cipherscan_debug off
```

Detections are always printed to console regardless of the debug setting — debug only controls the extra verbose status/HTTP logs.

Manage the whitelist live, no restart needed:

```
cipherscan_whitelist_add <resource>
```
```
cipherscan_whitelist_remove <resource>
```
```
cipherscan_whitelist_list
```

---

## ⚙️ Configuration

All settings are configurable from the `Config` table at the top of `compiled.lua`:

- Master `debug` switch (verbose logging on/off)
- Scan on startup, and startup delay
- Auto-scan resources that start after boot
- Optional periodic full rescans on an interval
- Detection score threshold before a file is reported
- Max file size scanned, and folder paths to skip (e.g. `node_modules`, `.git`, build output)
- **Whitelist** — a baked-in `Config.whitelist` name list, plus a live console-managed one that persists across restarts (see below)
- **Escrow / purchased-script exclusion** — auto-skip escrowed resources and a binary-content safety net (see below)
- **Discord webhook routing** — separate webhook URLs per alert category (detections / blocked actions / integrity / summaries), or one shared default; custom bot username + avatar
- `flagDiscordWebhooks` toggle — legitimate Discord webhook logging in *scanned* resources is allowed (not flagged) by default
- `allowedHosts` — hosts that always bypass the outbound HTTP guard (Discord's webhook domains are allow-listed out of the box)
- Enable/disable each runtime protection independently (HTTP guard, loader guard, shell-exec block, global self-healing, integrity checker)

---

## 🔍 Detection Engine

Every `.lua` / `.js` file (plus `fxmanifest.lua`) in every resource is scanned and scored — flagged files are reported as **SUSPICIOUS**, **HIGH**, or **CRITICAL** with the exact line number of each match:

- **Obfuscation decoding** — `\xNN` and decimal `\NNN` escape sequences are decoded before matching, so hex/escape-obfuscated payloads are caught the same as plain text. Natives that only appear *after* decoding (e.g. a hidden `PerformHttpRequest`) are flagged on their own.
- **Dynamic execution** — `assert(load())`, `loadstring`, nested loaders, and long inline `load([[...]])` blocks.
- **Bytecode injection** — raw precompiled Lua / LuaJIT bytecode blobs (`\27Lua`, `\27LJ` headers).
- **Exfiltration channels** — Pastebin, Hastebin, 0x0.st, and hard-coded IP URLs. Discord webhook URLs are recognized but **not flagged by default** (`flagDiscordWebhooks = false`), since legit admin/ban-log resources use them constantly — flip the config on if you want them scored again.
- **Credential / secret theft** — access to `sv_licenseKey`, `steam_webApiKey`, and database connection strings.
- **Environment hooking** — `setmetatable(_G)`, `rawset(_G)`, and dynamic `_G["..."]` access.
- **Shell execution** — `os.execute`, `io.popen`, and Node's `child_process`.
- **Obfuscator fingerprints** — `string.char()` floods, oversized base64-style literals, abnormally long identifiers, and runs of consecutive hex/decimal escapes.
- **Known malware signatures** — built-in markers for known cipher/backdoor infrastructure and artifacts (e.g. `ketamin.cc`, `cipher-panel`, `Enchanced_Tabs`, `helpCode`).

---

## 📋 Whitelist

Any resource can be excluded from scanning entirely, purely by preference — a trusted script, a noisy false positive, or anything you just don't want CipherScanner touching. There are two ways to whitelist a resource, and both are checked on every scan:

- **Config-defined** — list resource names in `Config.whitelist` at the top of `compiled.lua`. Baked in, survives restarts, requires editing the file.
- **Console-managed** — `cipherscan_whitelist_add <resource>` / `cipherscan_whitelist_remove <resource>` from the server console, no restart or file edit needed. These are stored in a resource KVP (`Config.whitelistKvpKey`, default `cipherscanner_whitelist`) so they persist across restarts on their own — set `Config.whitelistPersist = false` if you'd rather they reset every boot. `cipherscan_whitelist_list` shows both lists at once.

Matching is case-insensitive and by exact resource name.

---

## 🔐 Escrow & Third-Party Scripts

Encrypted/escrowed resources (Cfx.re asset escrow, and most premium/purchased scripts) can't be read as real source — `LoadResourceFile` only ever returns ciphertext or compiled binary for them, which used to trip the text-pattern heuristics with false positives. Two more layers, on top of the whitelist above, keep that content out of the scanner automatically — no manual whitelisting needed for most escrowed scripts:

- **Auto-detection** — any resource that declares an `escrow_ignore` block in its `fxmanifest.lua` is recognized as escrowed and skipped.
- **Binary-content safety net** — even without that, a file whose bytes don't look like readable text (encrypted or compiled content) is skipped rather than run through the heuristics, so it's never misreported as malware.

Skipped resources/files are counted separately in the scan summary so you can see what was excluded.

---

## 🔒 Runtime Protection

Beyond static scanning, CipherScanner hardens its own script environment and watches for tampering:

- **Guarded `PerformHttpRequest`, `load` / `loadstring`** — within CipherScanner's own runtime, blocks calls to known-malicious hosts, raw bytecode execution, and dynamically generated code that scores above the detection threshold. *(FXServer runs each resource in its own isolated script environment, so this guards CipherScanner's own execution path, not other resources' internal calls — the cross-resource protection comes from the file scanner above and the alerts below.)*
- **Outbound allowlist** — hosts in `Config.allowedHosts` (Discord's webhook domains by default) always pass straight through the guard.
- **Shell execution lockout** — neutralises `os.execute` and `io.popen` within CipherScanner's own environment.
- **Self-healing globals** — a background watcher restores the guarded HTTP and loader functions if something overwrites them.
- **File integrity monitoring** — every scanned file is hashed; if its content changes after load, it's automatically re-scanned and an alert is raised.
- **Auto-scan on resource start** — newly started resources are scanned automatically, even ones added after boot.
- **Multi-channel Discord webhook alerting** — route detections, blocked actions, integrity changes, and scan summaries to separate webhook URLs (or one shared default), with a custom bot name/avatar, rich embeds (resource, file, score, per-rule breakdown), delivery-failure logging, and automatic alert de-duplication.

---

## ⚡ Performance

- Recursive filesystem walk is done in a single call (no per-folder round trips), with configurable depth/file caps and skip lists for `node_modules`, `.git`, and build folders.
- Identical files across resources are hashed once and reused from cache instead of being re-analyzed.
- Large files are hashed via a bounded head/tail sample instead of reading the full contents.
- Scanning yields periodically so it never blocks the server's main thread/tick.

---

## 🧩 Use Cases

- Detecting known FiveM cipher / backdoor malware before it activates
- Catching obfuscated or hex-encoded malicious payloads other scanners miss
- Blocking unauthorized outbound HTTP requests and data exfiltration
- Preventing runtime bytecode injection and shell command execution
- Ongoing integrity monitoring against files modified after load
- Running cleanly alongside purchased/escrowed scripts without false-flagging them

---

## 👤 Author

Developed by **Zayed**. If this tool helps you, consider ⭐ starring the repository!

---

## 📄 License

This script is provided for public use. Reselling or claiming ownership is not permitted.
