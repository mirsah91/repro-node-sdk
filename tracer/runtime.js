// runtime.js
const { AsyncLocalStorage } = require('node:async_hooks');

const als = new AsyncLocalStorage(); // { traceId, depth }
const listeners = new Set();
let EMITTING = false;
const quiet = process.env.TRACE_QUIET === '1';

// ---- console patch: trace console.* as top-level calls (safe; no recursion) ----
let CONSOLE_PATCHED = false;
function patchConsole() {
    if (CONSOLE_PATCHED) return; CONSOLE_PATCHED = true;

    const orig = {};
    for (const m of ['log', 'info', 'warn', 'error', 'debug', 'trace']) {
        if (typeof console[m] !== 'function') continue;
        orig[m] = console[m];
        console[m] = function tracedConsoleMethod(...args) {
            // mark as core so it's obvious in logs
            trace.enter(`console.${m}`, { file: 'node:console', line: null });
            try {
                return orig[m].apply(this, args);
            } finally {
                trace.exit({ fn: `console.${m}`, file: 'node:console', line: null });
            }
        };
    }
}

const trace = {
    on(fn){ listeners.add(fn); return () => listeners.delete(fn); },
    withTrace(id, fn){ return als.run({ traceId: id, depth: 0 }, fn); },
    enter(fn, meta){
        const ctx = als.getStore() || {};
        ctx.depth = (ctx.depth || 0) + 1;
        emit({ type:'enter', t: Date.now(), fn, file: meta?.file, line: meta?.line,
            traceId: ctx.traceId, depth: ctx.depth });
    },
    exit(meta){
        const ctx = als.getStore() || {};
        emit({ type:'exit', t: Date.now(), fn: meta?.fn, file: meta?.file, line: meta?.line,
            traceId: ctx.traceId, depth: ctx.depth || 0 });
        ctx.depth = Math.max(0, (ctx.depth || 1) - 1);
    }
};
global.__trace = trace; // called by injected code

// ===== Symbols used by the loader to tag function origins =====
const SYM_SRC_FILE = Symbol.for('__repro_src_file'); // function's defining file (set by require hook)
const SYM_IS_APP   = Symbol.for('__repro_is_app');   // boolean: true if function is from app code
const SYM_SKIP_WRAP= Symbol.for('__repro_skip_wrap'); // guard to avoid wrapping our own helpers

function emit(ev){
    if (EMITTING) return;
    EMITTING = true;
    try { for (const l of listeners) l(ev); }
    finally { EMITTING = false; }
}

if (!quiet) {
    // ---- filtered logger: full detail for app code, top-level only for node_modules ----
    const isNodeModules = (file) => !!file && file.replace(/\\/g, '/').includes('/node_modules/');

    // per-trace logger state
    const stateByTrace = new Map();
    function getState(traceId) {
        const k = traceId || '__global__';
        let s = stateByTrace.get(k);
        if (!s) {
            s = { stack: [], muteDepth: null, lastLine: null, repeat: 0 };
            stateByTrace.set(k, s);
        }
        return s;
    }

    function flushRepeat(s) {
        if (s.repeat > 1) process.stdout.write(`  … ×${s.repeat - 1}\n`);
        s.repeat = 0;
        s.lastLine = null;
    }

    function printLine(ev, st) {
        const d = ev.depth || 0;
        const indent = '  '.repeat(Math.max(0, d - (ev.type === 'exit' ? 1 : 0)));
        const loc = ev.file ? ` (${short(ev.file)}:${ev.line ?? ''})` : '';
        const id  = ev.traceId ? `  [${ev.traceId}]` : '';
        const line = ev.type === 'enter'
            ? `${indent}→ enter ${ev.fn}${loc}${id}`
            : `${indent}← exit${id}`;

        // coalesce exact repeats
        if (line === st.lastLine) { st.repeat++; return; }
        if (st.repeat > 0) flushRepeat(st);
        process.stdout.write(line + '\n');
        st.lastLine = line; st.repeat = 1;
    }

    // Re-entrancy guard for emitting
    let IN_LOG = false;
    trace.on(ev => {
        if (IN_LOG) return;
        IN_LOG = true;
        try {
            const st = getState(ev.traceId);
            const nm = isNodeModules(ev.file);

            if (ev.type === 'enter') {
                const prev = st.stack.length ? st.stack[st.stack.length - 1] : null;
                const prevIsNM = prev ? prev.isNM : false;

                // If we are already muting deeper node_modules frames, and this is another dep frame at/under mute depth -> skip
                if (nm && st.muteDepth !== null && ev.depth >= st.muteDepth) {
                    st.stack.push({ isNM: true }); // keep structural parity
                    return;
                }

                // Crossing app -> dep: print this top-level dep fn, then mute deeper dep frames
                if (nm && !prevIsNM) {
                    printLine(ev, st);
                    st.muteDepth = ev.depth + 1;
                    st.stack.push({ isNM: true });
                    return;
                }

                // App code (or dep -> app bounce): always print
                printLine(ev, st);
                st.stack.push({ isNM: nm });
                return;
            }

            // EXIT
            if (ev.type === 'exit') {
                const cur = st.stack.length ? st.stack[st.stack.length - 1] : null;
                const curIsNM = cur ? cur.isNM : false;

                // If this is a muted nested dep frame, skip printing
                if (curIsNM && st.muteDepth !== null && ev.depth >= st.muteDepth) {
                    st.stack.pop();
                    return;
                }

                // Print exits for app frames and for the top-level dep frame
                printLine(ev, st);

                // If we just exited the top-level dep frame, unmute deeper deps
                if (curIsNM && st.muteDepth !== null && ev.depth === st.muteDepth - 1) {
                    st.muteDepth = null;
                }

                st.stack.pop();
                return;
            }
        } finally {
            IN_LOG = false;
        }
    });

    // flush any coalesced repeats before exiting
    process.on('beforeExit', () => {
        for (const s of stateByTrace.values()) flushRepeat(s);
    });
}

function short(p){ try{ const cwd = process.cwd().replace(/\\/g,'/'); return String(p).replace(cwd+'/',''); } catch { return p; } }

// ========= Generic call-site shim (used by Babel transform) =========
// Decides whether to emit a top-level event based on callee origin tags.
// No hardcoded library names or file paths.
if (!global.__repro_call) {
    Object.defineProperty(global, '__repro_call', {
        value: function __repro_call(fn, thisArg, args, callFile, callLine, label) {
            try {
                if (typeof fn !== 'function' || fn[SYM_SKIP_WRAP]) {
                    return fn.apply(thisArg, args);
                }

                const isApp = fn[SYM_IS_APP] === true;
                if (isApp) return fn.apply(thisArg, args);

                const name = label || fn.name || '(anonymous)';
                const meta = { file: callFile || null, line: callLine || null };

                trace.enter(name, meta);
                try {
                    const out = fn.apply(thisArg, args);

                    // --- classify the return value ---
                    const isThenable = out && typeof out.then === 'function';
                    const isNativePromise =
                        typeof Promise !== 'undefined' &&
                        (out instanceof Promise || out?.[Symbol.toStringTag] === 'Promise');

                    // Heuristic: Mongoose Query (thenable that has .exec and ctor name 'Query')
                    const isMongooseQuery =
                        isThenable &&
                        typeof out.exec === 'function' &&
                        (out?.constructor?.name === 'Query' || out?.model != null);

                    if (isThenable) {
                        if (isNativePromise) {
                            // Safe: attach side-effect, return the ORIGINAL promise
                            if (typeof out.finally === 'function') {
                                out.finally(() =>
                                    trace.exit({ fn: name, file: meta.file, line: meta.line })
                                );
                                return out;
                            }
                            // Rare thenables that are actually native-ish but no .finally
                            Promise.resolve(out).finally(() =>
                                trace.exit({ fn: name, file: meta.file, line: meta.line })
                            );
                            return out;
                        }

                        if (isMongooseQuery) {
                            // CRITICAL: do NOT attach handlers; they'd execute the query now.
                            // Emit exit immediately and return the original thenable Query for chaining.
                            trace.exit({ fn: name, file: meta.file, line: meta.line });
                            return out;
                        }

                        // Generic unknown thenable: don't replace it.
                        // Try to piggyback without touching its identity; if that throws, at least we emitted enter.
                        try {
                            Promise.resolve(out).finally(() =>
                                trace.exit({ fn: name, file: meta.file, line: meta.line })
                            );
                        } catch {
                            // fallback: immediate exit; better than leaking a span
                            trace.exit({ fn: name, file: meta.file, line: meta.line });
                        }
                        return out;
                    }

                    // Non-thenable: close span now
                    trace.exit({ fn: name, file: meta.file, line: meta.line });
                    return out;
                } catch (e) {
                    trace.exit({ fn: name, file: meta.file, line: meta.line });
                    throw e;
                }
            } catch {
                return fn ? fn.apply(thisArg, args) : undefined;
            }
        },
        configurable: false,
        writable: false,
        enumerable: false
    });
    // Guard our helper from any instrumentation
    global.__repro_call[SYM_SKIP_WRAP] = true;
}

// ---- automatic per-request context via http/https ----
function patchHttp(){
    try {
        const http = require('node:http');
        const Server = http.Server;
        const _emit = Server.prototype.emit;
        Server.prototype.emit = function(ev, req, res){
            if (ev === 'request' && req && res) {
                const id = `${req.method} ${req.url} #${(Math.random()*1e9|0).toString(36)}`;
                return trace.withTrace(id, () => _emit.call(this, ev, req, res));
            }
            return _emit.apply(this, arguments);
        };
        // https piggybacks http.Server in Node, no extra patch usually needed
    } catch {}
}

// ---- optional V8 sampling summary on SIGINT ----
let inspectorSession = null;
function startV8(samplingMs = 10){
    const inspector = require('node:inspector');
    inspectorSession = new inspector.Session();
    inspectorSession.connect();
    inspectorSession.post('Profiler.enable');
    inspectorSession.post('Profiler.setSamplingInterval', { interval: samplingMs * 1000 });
    inspectorSession.post('Profiler.start');
    if (!quiet) process.stdout.write(`[v8] profiler started @ ${samplingMs}ms\n`);
}
function stopV8(){ return new Promise((resolve, reject) => {
    if (!inspectorSession) return resolve(null);
    inspectorSession.post('Profiler.stop', (err, payload) => {
        if (err) return reject(err);
        try { inspectorSession.disconnect(); } catch {}
        inspectorSession = null;
        resolve(payload?.profile ?? null);
    });
});}
function summarize(profile, topN=10){
    if (!profile) return { top: [] };
    const nodes = new Map(profile.nodes.map(n=>[n.id,n]));
    const { samples=[], timeDeltas=[] } = profile;
    const self = new Map();
    for (let i=0;i<samples.length;i++) self.set(samples[i], (self.get(samples[i])||0)+(timeDeltas[i]||0));
    const top = [...self].map(([id,us])=>({node:nodes.get(id),ms:us/1000}))
        .sort((a,b)=>b.ms-a.ms).slice(0,topN)
        .map(({node,ms})=>({ ms:+ms.toFixed(2),
            fn: node?.callFrame?.functionName || '(anonymous)',
            url: node?.callFrame?.url, line: node?.callFrame?.lineNumber!=null ? node.callFrame.lineNumber+1 : undefined }));
    return { top };
}
async function printV8(){ const p=await stopV8(); const s=summarize(p);
    if (!quiet) { process.stdout.write('\n[v8] Top self-time:\n');
        for (const r of s.top) process.stdout.write(`  ${r.ms}ms  ${r.fn}  ${r.url ?? ''}:${r.line ?? ''}\n`);
    }
}

function getCurrentTraceId() {
    const s = als.getStore();
    return s && s.traceId || null;
}

module.exports = {
    trace,
    patchHttp,
    startV8,
    printV8,
    patchConsole,
    getCurrentTraceId,
    // export symbols so the require hook can tag function origins
    SYM_SRC_FILE,
    SYM_IS_APP,
    SYM_SKIP_WRAP
};
