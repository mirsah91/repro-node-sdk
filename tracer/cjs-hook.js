// cjs-hook.js
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const babel = require('@babel/core');
const tsPlugin =
    require('@babel/plugin-transform-typescript').default ||
    require('@babel/plugin-transform-typescript');

const makeWrap = require('./wrap-plugin');
// pull symbol definitions (and ensure runtime is initialized once)
const { SYM_SRC_FILE, SYM_IS_APP } = require('./runtime');

// ---------- helpers ----------
const CWD = process.cwd().replace(/\\/g, '/');
const escapeRx = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function isAppFile(filename) {
    const f = String(filename || '').replace(/\\/g, '/');
    return f.startsWith(CWD + '/') && !f.includes('/node_modules/');
}

function tagExports(value, filename, seen = new WeakSet(), depth = 0) {
    if (value == null) return;
    const ty = typeof value;
    if (ty !== 'object' && ty !== 'function') return;
    if (seen.has(value)) return;
    seen.add(value);

    const isApp = isAppFile(filename);

    if (typeof value === 'function') {
        try {
            if (!value[SYM_SRC_FILE]) {
                Object.defineProperty(value, SYM_SRC_FILE, { value: filename, configurable: false });
            }
            if (value[SYM_IS_APP] !== isApp) {
                Object.defineProperty(value, SYM_IS_APP, { value: isApp, configurable: false });
            }
        } catch {}
        const proto = value.prototype;
        if (proto && typeof proto === 'object') {
            for (const k of Object.getOwnPropertyNames(proto)) {
                if (k === 'constructor') continue;
                const d = Object.getOwnPropertyDescriptor(proto, k);
                if (d && typeof d.value === 'function') {
                    tagExports(d.value, filename, seen, depth + 1);
                }
            }
        }
    }

    if (typeof value === 'object' && depth < 4) {
        for (const k of Object.getOwnPropertyNames(value)) {
            const d = Object.getOwnPropertyDescriptor(value, k);
            if (!d) continue;
            tagExports(d.value, filename, seen, depth + 1);
        }
    }
}

// ---------- install ----------
function installCJS({ include, exclude, parserPlugins } = {}) {
    const ORIG = {
        js:  Module._extensions['.js'],
        jsx: Module._extensions['.jsx'] || Module._extensions['.js'],
        ts:  Module._extensions['.ts']  || Module._extensions['.js'],
        tsx: Module._extensions['.tsx'] || Module._extensions['.ts'] || Module._extensions['.js'],
    };

    // Default include = current project dir
    const DEFAULT_INCLUDE = [ new RegExp('^' + escapeRx(CWD + '/')) ];
    const inc = Array.isArray(include) && include.length ? include : DEFAULT_INCLUDE;
    const exc = Array.isArray(exclude) ? exclude : [];

    const shouldHandle = f => {
        const s = String(f || '').replace(/\\/g, '/');
        if (exc.some(rx => rx.test(s))) return false;
        return inc.some(rx => rx.test(s));
    };

    function handler(orig) {
        return function (module, filename) {
            if (!shouldHandle(filename)) {
                // Fall back to original loader
                return orig(module, filename);
            }
            try {
                const code = fs.readFileSync(filename, 'utf8');

                // Transform only app files (adds function-body enter/exit + call-site shim)
                const out = isAppFile(filename)
                    ? (babel.transformSync(code, {
                        filename,
                        sourceType: 'unambiguous',
                        retainLines: true,
                        parserOpts: {
                            sourceType: 'unambiguous',
                            plugins: parserPlugins || [
                                'jsx', 'typescript', 'classProperties', 'classPrivateProperties',
                                'classPrivateMethods', 'dynamicImport', 'topLevelAwait',
                                'optionalChaining', 'nullishCoalescingOperator',
                            ],
                        },
                        plugins: [
                            [ makeWrap(filename, { mode: 'all', wrapGettersSetters: false, skipAnonymous: false }) ],
                            [ tsPlugin, { allowDeclareFields: true } ],
                        ],
                        compact: false,
                        comments: true,
                    })?.code || code)
                    : code;

                module._compile(out, filename);
                // Tag exports for origin detection by __repro_call (both app & deps)
                try { tagExports(module.exports, filename); } catch {}
            } catch (e) {
                // On transform error, run original loader to avoid breaking the app
                return orig(module, filename);
            }
        };
    }

    Module._extensions['.js']  = handler(ORIG.js);
    Module._extensions['.jsx'] = handler(ORIG.jsx);
    Module._extensions['.ts']  = handler(ORIG.ts);
    Module._extensions['.tsx'] = handler(ORIG.tsx);

    // Tag exports for modules loaded via other pathways/extensions as well
    const _resolveFilename = Module._resolveFilename;
    const _load = Module._load;
    Module._load = function patchedLoad(request, parent, isMain) {
        const filename = (() => {
            try { return _resolveFilename.call(Module, request, parent, isMain); }
            catch { return String(request); } // e.g., builtins like 'node:fs'
        })();
        const exp = _load.apply(this, arguments);
        try { tagExports(exp, filename); } catch {}
        return exp;
    };
}

module.exports = { installCJS };
