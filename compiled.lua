-- ========================================
-- CipherScanner - anti-backdoor / anti-cipher scanner for FiveM (server)
-- ========================================
-- Static scan of every resource file + live runtime hardening against the
-- techniques modern FiveM ciphers / backdoors rely on:
--   * obfuscated dynamic execution   (assert(load()), loadstring, bytecode)
--   * hex / decimal string encoding  (hidden PerformHttpRequest, net events)
--   * outbound C2 / webhook exfil     (ketamin, cipher-panel, Discord webhooks)
--   * global environment hooks        (setmetatable(_G), HTTP function swap)
--   * shell execution                 (os.execute, io.popen)
--   * post-load file tampering        (integrity re-hashing)

-- ========================================
-- CONFIG
-- ========================================
local Config = {
    -- master debug switch: true = print everything, false = stay silent
    -- (detections are ALWAYS printed regardless of this flag)
    debug             = true,

    -- scanning
    scanOnStart       = true,
    startupDelay      = 5000,               -- ms after boot before the first scan
    scanNewResources  = true,               -- auto-scan resources started after boot
    periodicRescan    = false,              -- rescan everything on an interval
    rescanInterval    = 30 * 60 * 1000,
    reportThreshold   = 4,                  -- minimum score before a file is flagged
    maxFileBytes      = 6 * 1024 * 1024,    -- skip files larger than this
    yieldEvery        = 40,                 -- Wait(0) every N files to keep the tick smooth
    skipPathContains  = {                   -- lowercase fragments; matching files are skipped
        "/node_modules/", "/.git/", "/vendor/", "/dist/",
        "/web/build/", "/ui/build/", "/html/build/", "/nui/dist/",
    },

    -- escrow / third-party scripts
    -- Escrowed (Cfx.re asset-escrow) and other encrypted/compiled resources
    -- can't be read as real source - LoadResourceFile returns ciphertext or
    -- compiled binary for them, which trips text-pattern heuristics with
    -- false positives. These keep that content out of the scanner.
    skipEscrowed      = true,               -- auto-detect via fxmanifest `escrow_ignore`
    skipBinaryContent = true,               -- skip files that aren't readable text (safety net)

    -- whitelist: resources CipherScanner should never scan, purely by your
    -- own preference (trusted scripts, noisy false positives, anything you
    -- just don't want touched) - independent of whether it's escrowed.
    -- Names are case-insensitive. This is the baked-in list; resources can
    -- also be added/removed live from the server console (see the
    -- cipherscan_whitelist_* commands below) without editing this file.
    whitelist = {
        -- "my_purchased_script",
        -- "my_trusted_framework",
    },
    whitelistPersist = true,                -- console add/remove survives restarts (via KVP)
    whitelistKvpKey  = "cipherscanner_whitelist",

    -- runtime protection
    protectHttp       = true,               -- wrap + guard PerformHttpRequest
    protectLoaders    = true,               -- wrap load / loadstring
    blockShellExec    = true,               -- neutralise os.execute / io.popen
    protectGlobals    = true,               -- restore hooked globals automatically
    integrityCheck    = true,               -- re-hash scanned files, alert on changes
    integrityInterval = 5 * 60 * 1000,

    -- outbound-request allowlist: hosts here always bypass the malicious-URL
    -- guard, no matter what. Discord's webhook domains are allowed out of the
    -- box so your own logging resources are never touched by the HTTP guard.
    allowedHosts = {
        "discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com",
    },

    -- Discord webhooks in a SCANNED resource are common for legit admin/ban
    -- logs, so they are not treated as an exfiltration indicator by default.
    -- Flip to true if you want CipherScanner to flag them again.
    flagDiscordWebhooks = false,

    -- alerting (optional) --------------------------------------------------
    -- One or more Discord webhook URLs CipherScanner itself sends alerts to.
    -- Any category left blank falls back to `webhooks.default`.
    webhooks = {
        default    = "",   -- fallback used by every category below
        detections = "",   -- malware / suspicious file scan hits
        blocked    = "",   -- blocked HTTP / bytecode / shell-exec attempts
        integrity  = "",   -- files changed after load
        summary    = "",   -- end-of-scan summaries
    },
    webhookUsername = "CipherScanner",
    webhookAvatar   = "",   -- optional avatar_url for the webhook messages

    -- deprecated: kept for backwards compatibility with older configs;
    -- used as `webhooks.default` if that is left blank
    alertWebhook = "",
}

-- ========================================
-- CORE
-- ========================================
local RESOURCE  = GetCurrentResourceName()
local RealHttp  = PerformHttpRequest
local RealLoad  = load

local function dprint(msg)
    if Config.debug then print(("^5[CipherScanner]^7 %s"):format(msg)) end
end

-- ---- alerting -------------------------------------------------------------
-- kind -> { webhook config key, embed color }
local ALERT_KINDS = {
    detection = { key = "detections", color = 15158332 }, -- red
    blocked   = { key = "blocked",    color = 15105570 }, -- orange
    integrity = { key = "integrity",  color = 15844367 }, -- gold
    summary   = { key = "summary",    color = 5793266  }, -- blurple
}

local function webhookUrl(kind)
    local cfg = ALERT_KINDS[kind] or ALERT_KINDS.detection
    local w = Config.webhooks or {}
    local specific = w[cfg.key]
    if specific and specific ~= "" then return specific, cfg.color end
    local default = (w.default and w.default ~= "") and w.default or Config.alertWebhook
    return default, cfg.color
end

local lastAlert = {}
local function alert(kind, title, detail, fields)
    detail = tostring(detail or "")
    print(("^1[CipherScanner] ALERT^7 %s ^8-^7 %s"):format(title, detail))

    local url, color = webhookUrl(kind)
    if not url or url == "" then return end

    local key = kind .. "|" .. title .. "|" .. detail
    local now = GetGameTimer()
    if lastAlert[key] and (now - lastAlert[key]) < 60000 then return end
    lastAlert[key] = now

    local embed = {
        title       = tostring(title):sub(1, 240),
        description = detail:sub(1, 1800),
        color       = color,
        timestamp   = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        footer      = { text = ("server: %s"):format(GetConvar("sv_hostname", "unknown")) },
    }
    if fields and #fields > 0 then embed.fields = fields end

    local payload = { embeds = { embed } }
    if Config.webhookUsername and Config.webhookUsername ~= "" then
        payload.username = Config.webhookUsername
    end
    if Config.webhookAvatar and Config.webhookAvatar ~= "" then
        payload.avatar_url = Config.webhookAvatar
    end

    RealHttp(url, function(status)
        if status ~= 200 and status ~= 204 then
            dprint(("webhook delivery failed (%s): HTTP %s"):format(kind, tostring(status)))
        end
    end, "POST", json.encode(payload), { ["Content-Type"] = "application/json" })
end

-- ---- hashing -------------------------------------------------------------
local function djb2(s)
    local h = 5381
    for i = 1, #s do
        h = (h * 33 + s:byte(i)) % 4294967296
    end
    return ("%08x"):format(h)
end

local function hashContent(s)
    -- bound the work on huge files: head + tail + length is enough to spot
    -- tampering and to de-duplicate identical files across resources
    local sample = s
    if #s > 131072 then
        sample = s:sub(1, 65536) .. s:sub(-65536) .. ("#%d"):format(#s)
    end
    local ok, res = pcall(function() return exports[RESOURCE]:sha256(sample) end)
    if ok and type(res) == "string" and #res > 0 then return res end
    return djb2(sample)
end

-- ========================================
-- DETECTION ENGINE
-- ========================================

-- Decode \xNN and \NNN escapes so obfuscated payloads match the same rules
-- as plain-text ones.
local function decodeEscapes(s)
    s = s:gsub("\\x(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
    s = s:gsub("\\(%d%d?%d?)", function(d)
        local n = tonumber(d)
        if n and n < 256 then return string.char(n) end
        return "\\" .. d
    end)
    return s
end

-- plain substring indicators: { needle (lowercase), weight, description, category }
-- an entry's `category` can be gated off entirely via Config (see the
-- discord_webhook filter below analyze())
local INDICATORS = {
    -- dynamic execution
    { "assert(load(",                 5, "assert(load()) runtime execution" },
    { "loadstring(",                  4, "loadstring runtime execution" },
    { "load([[",                      3, "load() of a long string literal" },
    { "\27lua",                       9, "precompiled Lua bytecode blob" },
    { "\27lj",                        9, "LuaJIT bytecode blob" },
    -- shell / filesystem
    { "os.execute",                   7, "OS command execution (os.execute)" },
    { "io.popen",                     7, "shell pipe execution (io.popen)" },
    { "os.remove",                    3, "file deletion (os.remove)" },
    { "os.rename",                    3, "file rename (os.rename)" },
    -- exfiltration
    { "discord.com/api/webhooks",     6, "Discord webhook usage", "discord_webhook" },
    { "discordapp.com/api/webhooks",  6, "Discord webhook usage", "discord_webhook" },
    { "canary.discord.com/api/webhooks", 6, "Discord webhook usage", "discord_webhook" },
    { "ptb.discord.com/api/webhooks", 6, "Discord webhook usage", "discord_webhook" },
    { "pastebin.com/raw",             5, "remote payload from pastebin" },
    { "hastebin.com",                 3, "remote paste service" },
    { "0x0.st",                       3, "anonymous file host" },
    -- secret theft
    { "sv_licensekey",                7, "server license key access" },
    { "steam_webapikey",              3, "Steam Web API key access" },
    { "mysql_connection_string",      2, "database credential access" },
    -- environment hooks
    { "setmetatable(_g",              8, "global environment hook (setmetatable _G)" },
    { "rawset(_g",                    4, "raw global write (rawset _G)" },
    { "getmetatable(_g",              4, "global environment inspection" },
    { "executecommand(",             3, "console command execution" },
    -- known cipher / backdoor infrastructure & markers
    { "ketamin.cc",                  10, "known malware C2 host (ketamin.cc)" },
    { "cipher-panel",                10, "known cipher backdoor panel" },
    { "cipher-panel.me",             10, "known cipher backdoor panel" },
    { "cipher.lol",                  10, "known cipher backdoor host" },
    { "helpcode",                     6, "cipher backdoor marker (helpCode)" },
    { "helperserver",                6, "cipher backdoor marker (helperServer)" },
    { "enchanced_tabs",              8, "known backdoor artifact (Enchanced_Tabs)" },
    { "random_char",                 3, "common obfuscator artifact" },
    { "mpwxwqelmrjadflkmxvifnevfzvkatbivrvjboepyciqfpjzxjnpixedbotvibpdxqdojr", 10, "known cipher payload key" },
    -- JS-side
    { "child_process",                7, "Node child_process (shell execution)" },
    { "require(\"child_process\")",    8, "Node child_process require" },
    { "require('child_process')",     8, "Node child_process require" },
    { "process.binding(",             5, "low-level Node binding access" },
}

-- Lua-pattern heuristics: { pattern, weight, description }
local PATTERNS = {
    { "assert%s*%(%s*load%s*%(",                       5, "assert(load()) runtime execution" },
    { "load%s*%(%s*loadstring",                        4, "nested loader (load(loadstring(...)))" },
    { "_g%s*%[%s*[\"']",                               2, "dynamic global access via _G[\"...\"]" },
    { "https?://%d+%.%d+%.%d+%.%d+",                   3, "hard-coded IP URL" },
    { "\\x%x%x\\x%x%x\\x%x%x\\x%x%x",                  4, "4+ consecutive \\xNN escapes (string obfuscation)" },
    { "\\%d%d?%d?\\%d%d?%d?\\%d%d?%d?\\%d%d?%d?",      3, "4+ consecutive decimal escapes (string obfuscation)" },
}

-- native names that are a red flag when they only appear after decoding
local HIDDEN_NATIVES = {
    "performhttprequest", "registernetevent", "addeventhandler",
    "triggerclientevent", "executecommand", "loadresourcefile",
}

local function analyze(content)
    local raw    = content
    local lower  = content:lower()
    local dlow   = decodeEscapes(content):lower()
    local joined = dlow:gsub("['\"]%s*%.%.%s*['\"]", "")   -- collapse "a".."b" -> ab

    local hits, seen, score = {}, {}, 0
    local function add(weight, desc, pos)
        if weight <= 0 or seen[desc] then return end
        seen[desc] = true
        score = score + weight
        hits[#hits + 1] = { w = weight, desc = desc, pos = pos or 1 }
    end

    for _, ind in ipairs(INDICATORS) do
        if ind[4] ~= "discord_webhook" or Config.flagDiscordWebhooks then
            local p = lower:find(ind[1], 1, true) or joined:find(ind[1], 1, true)
            if p then add(ind[2], ind[3], p) end
        end
    end

    for _, pt in ipairs(PATTERNS) do
        local p = lower:find(pt[1]) or raw:find(pt[1])
        if p then add(pt[2], pt[3], p) end
    end

    for _, name in ipairs(HIDDEN_NATIVES) do
        local p = dlow:find(name, 1, true)
        if p and not lower:find(name, 1, true) then
            add(8, ("hidden '%s' revealed only after decoding escapes"):format(name), p)
        end
    end

    local _, charCalls = lower:gsub("string%.char", "")
    if charCalls >= 8 then
        add(3, ("repeated string.char() calls (%d)"):format(charCalls))
    end

    -- gmatch-based heuristics are O(n) in allocations; skip them on huge
    -- (usually minified/bundled) files where the plain scans already ran
    if #raw <= 524288 then
        for blob in raw:gmatch("[\"']([A-Za-z0-9+/]+=?=?)[\"']") do
            if #blob >= 240 then
                add(3, ("large base64-like literal (%d chars)"):format(#blob))
                break
            end
        end

        local longest = 0
        for id in raw:gmatch("[%a_][%w_]*") do
            if #id > longest then longest = #id end
            if longest >= 48 then break end
        end
        if longest >= 48 then
            add(2, ("very long identifier (%d chars)"):format(longest))
        end
    end

    return score, hits
end

local function severity(score)
    if score >= 12 then return "CRITICAL" end
    if score >= 8  then return "HIGH" end
    if score >= Config.reportThreshold then return "SUSPICIOUS" end
    return nil
end

-- ---- line-number lookup (precomputed per file) --------------------------
local function newlineIndex(content)
    local idx, p = {}, content:find("\n", 1, true)
    while p do
        idx[#idx + 1] = p
        p = content:find("\n", p + 1, true)
    end
    return idx
end

local function lineFor(idx, pos)
    local lo, hi = 1, #idx
    while lo <= hi do
        local mid = math.floor((lo + hi) / 2)
        if idx[mid] < pos then lo = mid + 1 else hi = mid - 1 end
    end
    return lo
end

-- ========================================
-- SCANNER
-- ========================================
local scannedHashes, contentCache = {}, {}
local stats = { files = 0, flagged = 0, resourcesSkipped = 0, filesSkippedBinary = 0 }

-- ---- whitelist (personal-preference + escrow skip) ------------------------

-- baked-in whitelist from Config (kept for backwards compatibility with the
-- older `Config.skipResources` name too, so existing configs don't break)
local staticWhitelist = {}
for _, name in ipairs(Config.whitelist or {}) do
    staticWhitelist[name:lower()] = true
end
for _, name in ipairs(Config.skipResources or {}) do
    staticWhitelist[name:lower()] = true
end

local function kvpAvailable()
    return type(GetResourceKvpString) == "function" and type(SetResourceKvp) == "function"
end

-- resources added/removed live via cipherscan_whitelist_add/remove, kept in
-- sync with a KVP entry so they survive a resource/server restart
local function loadRuntimeWhitelist()
    local set = {}
    if not (Config.whitelistPersist and kvpAvailable()) then return set end
    local ok, raw = pcall(GetResourceKvpString, Config.whitelistKvpKey)
    if ok and raw and raw ~= "" then
        local ok2, list = pcall(json.decode, raw)
        if ok2 and type(list) == "table" then
            for _, name in ipairs(list) do
                if type(name) == "string" then set[name:lower()] = true end
            end
        end
    end
    return set
end

local runtimeWhitelist = loadRuntimeWhitelist()

local function saveRuntimeWhitelist()
    if not (Config.whitelistPersist and kvpAvailable()) then return end
    local list = {}
    for name in pairs(runtimeWhitelist) do list[#list + 1] = name end
    pcall(SetResourceKvp, Config.whitelistKvpKey, json.encode(list))
end

-- Resources that ship any `escrow_ignore` entry in fxmanifest are, by
-- definition, using Cfx.re asset escrow for everything else - their real
-- source isn't readable via LoadResourceFile, only ciphertext/bytecode is.
local function isEscrowed(resource)
    local ok, n = pcall(GetNumResourceMetadata, resource, "escrow_ignore")
    return ok and type(n) == "number" and n > 0
end

local function isSkippedResource(resource)
    local lower = resource:lower()
    if staticWhitelist[lower] or runtimeWhitelist[lower] then return true end
    if Config.skipEscrowed and isEscrowed(resource) then return true end
    return false
end

-- Cheap text/binary sniff: encrypted or compiled content reads as near-random
-- bytes, unlike real Lua/JS source. Used as a safety net for escrowed or
-- otherwise packed files that don't declare themselves via escrow_ignore.
local function looksBinary(content)
    local n = math.min(#content, 4096)
    if n == 0 then return false end
    local bad = 0
    for i = 1, n do
        local b = content:byte(i)
        if b == 0 then return true end
        if not ((b >= 32 and b <= 126) or b == 9 or b == 10 or b == 13) then
            bad = bad + 1
        end
    end
    return (bad / n) > 0.15
end

local function report(resource, relPath, score, hits, content)
    stats.flagged = stats.flagged + 1
    local nl = newlineIndex(content)
    print(("^1[CipherScanner] %s^7  %s/%s  ^3(score %d)^7")
        :format(severity(score), resource, relPath, score))
    for _, hit in ipairs(hits) do
        print(("   ^1-^7 line %d  ^3[w%d]^7 %s"):format(lineFor(nl, hit.pos), hit.w, hit.desc))
    end

    local ruleLines = {}
    for _, hit in ipairs(hits) do
        ruleLines[#ruleLines + 1] = ("line %d - [w%d] %s"):format(lineFor(nl, hit.pos), hit.w, hit.desc)
    end

    alert("detection", ("%s detection in %s"):format(severity(score), resource),
        table.concat(ruleLines, "\n"):sub(1, 1800), {
            { name = "Resource", value = resource, inline = true },
            { name = "File",     value = relPath,   inline = true },
            { name = "Score",    value = tostring(score), inline = true },
        })
end

local function shouldSkipPath(relPath)
    local p = relPath:lower()
    for _, frag in ipairs(Config.skipPathContains) do
        if p:find(frag, 1, true) then return true end
    end
    return false
end

local function scanFile(resource, relPath)
    local ext = relPath:match("%.([%w]+)$")
    ext = ext and ext:lower() or nil
    local isManifest = relPath:find("fxmanifest.lua", 1, true)
        or relPath:find("__resource.lua", 1, true)
    if not (ext == "lua" or ext == "js" or isManifest) then return end
    if shouldSkipPath(relPath) then return end

    local content = LoadResourceFile(resource, relPath)
    if not content or #content == 0 then return end
    if #content > Config.maxFileBytes then
        dprint(("skip (%.1f MB): %s/%s"):format(#content / 1048576, resource, relPath))
        return
    end
    if Config.skipBinaryContent and looksBinary(content) then
        stats.filesSkippedBinary = stats.filesSkippedBinary + 1
        dprint(("skip (binary/encrypted content, likely escrow): %s/%s"):format(resource, relPath))
        return
    end

    stats.files = stats.files + 1

    local h = hashContent(content)
    scannedHashes[resource .. "::" .. relPath] = h

    local cached = contentCache[h]
    if cached then
        if cached.score and severity(cached.score) then
            report(resource, relPath, cached.score, cached.hits, content)
        end
        return
    end

    local ok, score, hits = pcall(analyze, content)
    if not ok then
        dprint(("analyze error %s/%s: %s"):format(resource, relPath, tostring(score)))
        return
    end
    contentCache[h] = { score = score, hits = hits }
    if severity(score) then
        report(resource, relPath, score, hits, content)
    end
end

local function scanResource(resource)
    if resource == RESOURCE or resource == "_cfx_internal" then return end
    local state = GetResourceState(resource)
    if state ~= "started" and state ~= "starting" then return end
    if isSkippedResource(resource) then
        stats.resourcesSkipped = stats.resourcesSkipped + 1
        dprint(("skipping escrowed/whitelisted resource: %s"):format(resource))
        return
    end

    local files
    local ok, res = pcall(function()
        return exports[RESOURCE]:listFiles(GetResourcePath(resource))
    end)
    if ok and type(res) == "table" then files = res end

    if files and #files > 0 then
        for i = 1, #files do
            scanFile(resource, files[i])
            if i % Config.yieldEvery == 0 then Wait(0) end
        end
        return
    end

    -- fallback: scan the script files declared in the manifest
    dprint(("listFiles unavailable for %s, using manifest fallback"):format(resource))
    for _, key in ipairs({ "client_script", "server_script", "shared_script", "file" }) do
        local n = GetNumResourceMetadata(resource, key) or 0
        for i = 0, n - 1 do
            local rel = GetResourceMetadata(resource, key, i)
            if rel and not rel:find("*", 1, true) then scanFile(resource, rel) end
        end
    end
    scanFile(resource, "fxmanifest.lua")
end

local scanning = false
local function fullScan(trigger)
    if scanning then dprint("scan already running") return end
    scanning = true
    stats.files, stats.flagged, stats.resourcesSkipped, stats.filesSkippedBinary = 0, 0, 0, 0
    local started = GetGameTimer()
    dprint(("full scan started (%s)"):format(trigger or "manual"))

    for i = 0, GetNumResources() - 1 do
        local resource = GetResourceByFindIndex(i)
        if resource and resource ~= "_cfx_internal" and resource ~= RESOURCE then
            local okr, err = pcall(scanResource, resource)
            if not okr then dprint(("error scanning %s: %s"):format(resource, tostring(err))) end
            Wait(0)
        end
    end

    print(("^2[CipherScanner]^7 scan complete ^8-^7 %d files, ^1%d flagged^7, "
        .. "%d resource(s) skipped (escrow/whitelist), %d binary file(s) skipped, %.1fs")
        :format(stats.files, stats.flagged, stats.resourcesSkipped, stats.filesSkippedBinary,
            (GetGameTimer() - started) / 1000))
    if stats.flagged > 0 then
        alert("summary", "Scan finished with detections",
            ("%d file(s) flagged across the server"):format(stats.flagged))
    end
    scanning = false
end

-- ========================================
-- RUNTIME PROTECTION
-- ========================================
local BAD_HOST_PATTERNS = {
    "ketamin", "cipher%-panel", "cipherpanel", "cipher%.lol", "helperserver",
}

local function urlLooksMalicious(url)
    url = tostring(url):lower()
    for _, pat in ipairs(BAD_HOST_PATTERNS) do
        if url:find(pat) then return true end
    end
    return false
end

local function isAllowedHost(url)
    url = tostring(url):lower()
    for _, host in ipairs(Config.allowedHosts or {}) do
        if url:find(host:lower(), 1, true) then return true end
    end
    return false
end

-- ---- HTTP guard --------------------------------------------------------
local GuardedHttp
GuardedHttp = function(url, cb, method, data, headers, options)
    if isAllowedHost(url) then
        return RealHttp(url, cb, method, data, headers, options)
    end
    if urlLooksMalicious(url) then
        alert("blocked", "Blocked outbound HTTP", tostring(url))
        if cb then pcall(cb, 0, "", {}, "blocked-by-cipherscanner") end
        return
    end
    dprint(("HTTP %s %s"):format(tostring(method or "GET"), tostring(url)))
    return RealHttp(url, cb, method, data, headers, options)
end
if Config.protectHttp then
    _G.PerformHttpRequest = GuardedHttp
end

-- ---- loader guard ----------------------------------------------------
local GuardedLoad
local function guardChunk(chunk, name)
    if type(chunk) ~= "string" then return nil end
    if chunk:byte(1) == 27 then
        alert("blocked", "Blocked Lua bytecode load", tostring(name or "?"))
        return "bytecode"
    end
    local score = select(1, analyze(chunk))
    if score >= (Config.reportThreshold + 2) then
        alert("blocked", "Blocked suspicious dynamic code",
            ("load(%s) score %d"):format(tostring(name or "?"), score))
        return "suspicious"
    end
    if #chunk > 2000 then
        dprint(("large dynamic chunk: %d bytes (%s)"):format(#chunk, tostring(name or "?")))
    end
    return nil
end

GuardedLoad = function(chunk, chunkname, mode, env)
    local bad = guardChunk(chunk, chunkname)
    if bad then return nil, "blocked by CipherScanner: " .. bad end
    return RealLoad(chunk, chunkname, mode, env)
end

if Config.protectLoaders then
    _G.load = GuardedLoad
    if type(loadstring) == "function" then
        _G.loadstring = function(chunk, chunkname)
            local bad = guardChunk(chunk, chunkname)
            if bad then return nil, "blocked by CipherScanner: " .. bad end
            return RealLoad(chunk, chunkname)
        end
    end
end

-- ---- shell execution guard -----------------------------------------
if Config.blockShellExec then
    pcall(function()
        if os and os.execute then
            os.execute = function(cmd)
                alert("blocked", "Blocked os.execute", tostring(cmd))
                return nil
            end
        end
        if io and io.popen then
            io.popen = function(cmd)
                alert("blocked", "Blocked io.popen", tostring(cmd))
                return nil
            end
        end
    end)
end

-- ---- global integrity guardian ----------------------------------
if Config.protectGlobals then
    CreateThread(function()
        while true do
            Wait(1000)
            if Config.protectHttp and PerformHttpRequest ~= GuardedHttp then
                alert("blocked", "PerformHttpRequest was replaced", "restoring guarded version")
                _G.PerformHttpRequest = GuardedHttp
            end
            if Config.protectLoaders and load ~= GuardedLoad then
                alert("blocked", "load() was replaced", "restoring guarded version")
                _G.load = GuardedLoad
            end
        end
    end)
end

-- ========================================
-- STARTUP / SCHEDULES
-- ========================================
CreateThread(function()
    Wait(Config.startupDelay)
    if Config.scanOnStart then fullScan("startup") end

    if Config.periodicRescan then
        while true do
            Wait(Config.rescanInterval)
            fullScan("periodic")
        end
    end
end)

if Config.integrityCheck then
    CreateThread(function()
        Wait(Config.startupDelay + 60000)
        while true do
            Wait(Config.integrityInterval)
            local changed = 0
            for key, old in pairs(scannedHashes) do
                local resource, rel = key:match("^(.-)::(.+)$")
                if resource then
                    local c = LoadResourceFile(resource, rel)
                    if c then
                        local newHash = hashContent(c)
                        if newHash ~= old then
                            changed = changed + 1
                            scannedHashes[key] = newHash
                            alert("integrity", "File changed after load", key)
                            local score, hits = analyze(c)
                            if severity(score) then report(resource, rel, score, hits, c) end
                        end
                    end
                end
                Wait(0)
            end
            if changed > 0 then dprint(("integrity: %d file(s) changed"):format(changed)) end
        end
    end)
end

if Config.scanNewResources then
    AddEventHandler("onResourceStart", function(resource)
        if resource == RESOURCE then return end
        CreateThread(function()
            Wait(2000)
            dprint(("scanning newly started resource: %s"):format(resource))
            local ok, err = pcall(scanResource, resource)
            if not ok then dprint(("scan error (%s): %s"):format(resource, tostring(err))) end
        end)
    end)
end

-- ========================================
-- CONSOLE COMMANDS  (server console only)
-- ========================================
RegisterCommand("cipherscan", function(src)
    if src ~= 0 then return end
    fullScan("command")
end, true)

RegisterCommand("cipherscan_res", function(src, args)
    if src ~= 0 then return end
    local target = args[1]
    if not target then print("usage: cipherscan_res <resource>") return end
    stats.files, stats.flagged = 0, 0
    print(("^3[CipherScanner]^7 scanning %s ..."):format(target))
    pcall(scanResource, target)
    print(("^2[CipherScanner]^7 %s: %d files, %d flagged")
        :format(target, stats.files, stats.flagged))
end, true)

RegisterCommand("cipherscan_debug", function(src, args)
    if src ~= 0 then return end
    Config.debug = (args[1] == "on" or args[1] == "1" or args[1] == "true")
    print(("^3[CipherScanner]^7 debug = %s"):format(tostring(Config.debug)))
end, true)

RegisterCommand("cipherscan_whitelist_add", function(src, args)
    if src ~= 0 then return end
    local target = args[1]
    if not target then print("usage: cipherscan_whitelist_add <resource>") return end
    runtimeWhitelist[target:lower()] = true
    saveRuntimeWhitelist()
    print(("^2[CipherScanner]^7 whitelisted '%s' - it will be skipped from now on"):format(target))
end, true)

RegisterCommand("cipherscan_whitelist_remove", function(src, args)
    if src ~= 0 then return end
    local target = args[1]
    if not target then print("usage: cipherscan_whitelist_remove <resource>") return end
    if staticWhitelist[target:lower()] then
        print(("^3[CipherScanner]^7 '%s' is baked into Config.whitelist - remove it there too, "
            .. "or it'll stay whitelisted after a restart"):format(target))
    end
    runtimeWhitelist[target:lower()] = nil
    saveRuntimeWhitelist()
    print(("^3[CipherScanner]^7 '%s' removed from the runtime whitelist"):format(target))
end, true)

RegisterCommand("cipherscan_whitelist_list", function(src)
    if src ~= 0 then return end
    print("^3[CipherScanner]^7 whitelist (Config.whitelist, baked-in):")
    for name in pairs(staticWhitelist) do print("  - " .. name) end
    print("^3[CipherScanner]^7 whitelist (runtime, console-managed):")
    for name in pairs(runtimeWhitelist) do print("  - " .. name) end
end, true)
