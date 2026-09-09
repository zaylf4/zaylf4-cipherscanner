// ========================================
// CipherScanner - server helpers & JS-side protection
// ========================================
// Provides the filesystem exports the Lua scanner uses, a real SHA-256 for
// integrity checks, and keeps the known "miaus" backdoor threads neutralised.

const fs = require("fs");
const path = require("path");
let crypto = null;
try { crypto = require("crypto"); } catch (e) { /* crypto unavailable on this build */ }

// ----------------------------------------
// config / debug switch
// ----------------------------------------
const Config = {
    debug: true,                 // true = print everything, false = stay silent
    maxWalkDepth: 12,            // how deep listFiles() recurses
    maxFiles: 25000,            // hard cap on files returned per resource
    skipDirs: [                  // directory names never walked (lowercase)
        "node_modules", ".git", ".github", ".vscode",
        "stream", "vendor", "dist", "build", "cache",
    ],
};

function dlog(...args) {
    if (Config.debug) console.log("[CipherScanner]", ...args);
}

// only allow this resource's own scripts to call the exports
function selfOnly() {
    return GetInvokingResource() === GetCurrentResourceName();
}

// ========================================
// SECTION 1: FILESYSTEM EXPORTS
// ========================================

exports("readDir", function (dir) {
    if (!selfOnly()) return false;
    try {
        return fs.readdirSync(path.normalize(dir));
    } catch (e) {
        return [];
    }
});

exports("isDir", function (target) {
    if (!selfOnly()) return false;
    try {
        return fs.statSync(path.normalize(target)).isDirectory();
    } catch (e) {
        return false;
    }
});

// Recursively list every file under `root`, returned as forward-slash relative
// paths. One export call replaces the old per-directory round trips.
exports("listFiles", function (root) {
    if (!selfOnly()) return false;

    const base = path.normalize(root);
    const skip = new Set(Config.skipDirs);
    const out = [];
    let count = 0;

    const walk = (absDir, relDir, depth) => {
        if (depth > Config.maxWalkDepth || count >= Config.maxFiles) return;

        let entries;
        try {
            entries = fs.readdirSync(absDir, { withFileTypes: true });
        } catch (e) {
            return;
        }

        for (const entry of entries) {
            const name = entry.name;
            if (name.startsWith(".")) continue;

            const childAbs = path.join(absDir, name);
            const childRel = relDir ? relDir + "/" + name : name;

            let isDirectory = entry.isDirectory();
            if (entry.isSymbolicLink()) {
                try {
                    isDirectory = fs.statSync(childAbs).isDirectory();
                } catch (e) {
                    continue; // dangling / unreadable link
                }
            }

            if (isDirectory) {
                if (!skip.has(name.toLowerCase())) walk(childAbs, childRel, depth + 1);
            } else {
                out.push(childRel);
                if (++count >= Config.maxFiles) return;
            }
        }
    };

    walk(base, "", 0);
    return out;
});

// Real content hash for the integrity checker (djb2 fallback lives in Lua).
exports("sha256", function (text) {
    if (!selfOnly()) return false;
    if (!crypto) return null;
    try {
        return crypto.createHash("sha256").update(String(text || "")).digest("hex");
    } catch (e) {
        return null;
    }
});

// ========================================
// SECTION 2: MALWARE PREVENTION (thread-name lock)
// ========================================
setImmediate(() => {
    const badThreadNames = ["miaus", "miauss", "miausss", "miaussss"];

    globalThis.GlobalState = globalThis.GlobalState || {};

    const enforce = () => {
        for (const name of badThreadNames) {
            if (globalThis.GlobalState[name] !== "Prevention") {
                globalThis.GlobalState[name] = "Prevention";
            }
        }
    };

    enforce();
    setInterval(enforce, 1000);
    dlog("thread-name prevention active");
});
