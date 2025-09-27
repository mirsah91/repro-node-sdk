// index.ts
/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Request, Response, NextFunction } from 'express';
import type { Schema, Model, Query } from 'mongoose';
import * as mongoose from 'mongoose';
import { AsyncLocalStorage } from 'async_hooks';
import * as path from 'path';

// ---- tracer auto-init (no client -r needed) ------------------------
type TracerApi = {
    init: (opts: any) => any;
    tracer: { on: (fn: (ev: any) => void) => () => void };
    getCurrentTraceId?: () => string | null;
};

function escapeRx(s: string) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function safeResolveDir(mod: string): string | null {
    try { return path.dirname(require.resolve(mod + '/package.json')).replace(/\\/g, '/'); }
    catch { return null; }
}

let __TRACER_READY = false;
let tracerPkg: TracerApi;

(function ensureTracerInstalledOnce() {
    if (__TRACER_READY) return;

    // require your bundled tracer (folder in this package root)
    tracerPkg = require('../tracer') as TracerApi;

    const cwd = process.cwd().replace(/\\/g, '/');
    const sdkRoot = __dirname.replace(/\\/g, '/');

    // instrument: app code (exclude its node_modules), + targeted deps
    const projectNoNodeModules = new RegExp('^' + escapeRx(cwd) + '/(?!node_modules/)');
    const expressDir = safeResolveDir('express');
    const mongooseDir = safeResolveDir('mongoose');

    const include: RegExp[] = [ projectNoNodeModules ];
    if (expressDir)  include.push(new RegExp('^' + escapeRx(expressDir)  + '/'));
    if (mongooseDir) include.push(new RegExp('^' + escapeRx(mongooseDir) + '/'));

    const exclude: RegExp[] = [
        new RegExp('^' + escapeRx(sdkRoot) + '/'),     // don't instrument the SDK itself
        /node_modules[\\/]@babel[\\/].*/,              // never touch Babel internals
    ];

    // start tracer (idempotent inside tracer)
    tracerPkg.init({
        instrument: true,
        mode: process.env.TRACE_MODE || 'v8',
        samplingMs: 10,
        include,
        exclude,
    });

    __TRACER_READY = true;
})();

type CallEvent = { name: string; t: number; phase: 'enter' | 'exit' };
type Ctx = { sid?: string; aid?: string; calls?: CallEvent[] };
const als = new AsyncLocalStorage<Ctx>();
const getCtx = () => als.getStore() || {};

function logLine(s: string) {
    try { process.stdout.write(s + '\n'); } catch {}
}

// ===================================================================
// EXPRESS GLOBAL PATCH — wrap all handlers so they show in trace
// ===================================================================
let EXPRESS_PATCHED = false;
function patchExpressOnce() {
    if (EXPRESS_PATCHED) return;
    EXPRESS_PATCHED = true;

    let express: any;
    try { express = require('express'); } catch { return; }

    const RP = express?.Router?.prototype;
    if (!RP || (RP as any).__repro_patched) return;
    (RP as any).__repro_patched = true;

    const methods = ['use','all','get','post','put','patch','delete','options','head'];

    const wrapFn = (name: string, fn: Function) => {
        if (typeof fn !== 'function') return fn;
        const wrapped = function wrapped(this: any, ...args: any[]) {
            (global as any).__repro_traceEnter(name);
            try { return fn.apply(this, args); }
            finally { (global as any).__repro_traceExit(); }
        };
        try { Object.defineProperty(wrapped, 'name', { value: name, configurable: true }); } catch {}
        return wrapped;
    };

    const flatten = (arr: any[]): any[] => {
        const out: any[] = [];
        for (const a of arr) Array.isArray(a) ? out.push(...flatten(a)) : out.push(a);
        return out;
    };

    for (const m of methods) {
        const orig = RP[m];
        if (!orig) continue;
        RP[m] = function patchedMethod(this: any, ...args: any[]) {
            let base = '';
            if (typeof args[0] === 'string') base = args[0];
            else if (args[0] && args[0].fast_slash) base = '/';

            const flat = flatten(args);
            const rebuilt = flat.map((h: any) => {
                if (typeof h === 'function') {
                    const label = (m.toUpperCase() === 'USE') ? `MWARE ${base || '(router)'}` : `${m.toUpperCase()} ${base || '(dynamic)'}`;
                    return wrapFn(`${label} handler`, h);
                }
                return h;
            });
            return orig.apply(this, rebuilt);
        };
    }

    logLine('[repro] express router patched for call tracing');
}
patchExpressOnce();

// ===================================================================
// CONSOLE SHIM — attribute console.* to caller function (skip tracer)
// ===================================================================
let CONSOLE_PATCHED = false;
function patchConsoleOnce() {
    if (CONSOLE_PATCHED) return;
    CONSOLE_PATCHED = true;

    const c: any = console as any;
    if (c.__repro_patched) return;
    c.__repro_patched = true;

    const TRACER_FILE = __filename.replace(/\\/g, '/');

    const mk = (orig: Function) => {
        return function patchedConsole(this: any, ...args: any[]) {
            // derive caller name; skip if coming from tracer code
            let caller = '';
            let skip = false;
            try {
                const stack = new Error().stack?.split('\n') || [];
                // find first frame that is NOT our own file and not our tracer helpers
                for (let i = 2; i < Math.min(stack.length, 10); i++) {
                    const frame = stack[i] || '';
                    if (frame.includes(TRACER_FILE)) { continue; }
                    if (frame.includes('__repro_traceEnter') || frame.includes('__repro_traceExit')) { skip = true; break; }
                    const m = frame.match(/at\s+([^\s(]+)\s*\(/) || frame.match(/at\s+([^\s(]+)\s*$/);
                    const n = m?.[1];
                    if (n && !n.includes('/')) { caller = n; break; }
                }
            } catch {}

            if (!skip && caller) {
                try { (global as any).__repro_traceEnter(caller); } catch {}
                try { /* no-op */ } finally { try { (global as any).__repro_traceExit(); } catch {} }
            }
            return (orig as any).apply(this, args);
        };
    };

    c.log   = mk(c.log);
    c.info  = mk(c.info);
    c.warn  = mk(c.warn);
    c.error = mk(c.error);
    c.debug = mk(c.debug ?? c.log);
    // NOTE: we do NOT log here via console to avoid self-capture
    logLine('[repro] console patched for call tracing');
}
patchConsoleOnce();

// ===================================================================
// Optional pirates/Babel source tracing (best effort; safe to miss)
// ===================================================================
let TRACE_INSTALLED = false;
function installFunctionTracerOnce() {
    if (TRACE_INSTALLED) return;
    TRACE_INSTALLED = true;

    const appRoot = process.cwd();
    const loadedAppFiles = Object.keys(require.cache || {})
        .filter(f => f.startsWith(appRoot) && !f.includes('node_modules'));

    let pirates: any, parser: any, traverse: any, generator: any, t: any;
    try {
        pirates = require('pirates');
        parser = require('@babel/parser');
        traverse = require('@babel/traverse').default;
        generator = require('@babel/generator').default;
        t = require('@babel/types');
    } catch {
        logLine('[repro] function-call tracer unavailable: npm i pirates @babel/core @babel/parser @babel/traverse @babel/generator @babel/types --save');
        return;
    }

    const pkgDir = __dirname;
    const isFromApp = (filename: string) => {
        const f = path.resolve(filename);
        if (f.includes('node_modules')) return false;
        if (f.startsWith(pkgDir)) return false;
        return f.startsWith(appRoot);
    };

    const alreadyTagged = (node: any) =>
        node?.leadingComments?.some((c: any) => String(c.value || '').includes('@repro_instrumented'));

    function functionDisplayName(p: any): string {
        const n = p.node;
        if (t.isFunctionDeclaration(n) && n.id?.name) return n.id.name;
        if (t.isVariableDeclarator(p.parent) && t.isIdentifier(p.parent.id)) return p.parent.id.name;
        if ((t.isClassMethod(n) || t.isObjectMethod(n)) && t.isIdentifier(n.key)) return n.key.name;
        if (t.isObjectProperty(p.parent) && t.isIdentifier(p.parent.key)) return p.parent.key.name;
        return '<anonymous>';
    }

    function wrapFunctionBody(p: any) {
        const name = functionDisplayName(p);
        if (t.isArrowFunctionExpression(p.node) && !t.isBlockStatement(p.node.body)) {
            p.node.body = t.blockStatement([t.returnStatement(p.node.body as any)]);
        }
        const body: any = p.node.body;
        if (!t.isBlockStatement(body)) return;

        if (!alreadyTagged(p.node)) {
            (p.node.leadingComments || (p.node.leadingComments = [])).push(
                t.commentLine(' @repro_instrumented ')
            );
            const enterCall = t.expressionStatement(
                t.callExpression(t.identifier('__repro_traceEnter'), [t.stringLiteral(name)])
            );
            const tryStmt = t.tryStatement(
                t.blockStatement(body.body),
                null,
                t.blockStatement([
                    t.expressionStatement(t.callExpression(t.identifier('__repro_traceExit'), [])),
                ])
            );
            p.node.body = t.blockStatement([enterCall, tryStmt]);
        }
    }

    const transform = (code: string): string => {
        try {
            const ast = parser.parse(code, {
                sourceType: 'unambiguous',
                plugins: [
                    'jsx','typescript','classProperties','classPrivateProperties','classPrivateMethods',
                    'dynamicImport','optionalChaining','nullishCoalescingOperator','topLevelAwait',
                ],
            });
            traverse(ast, {
                FunctionDeclaration: wrapFunctionBody,
                FunctionExpression: wrapFunctionBody,
                ArrowFunctionExpression: wrapFunctionBody,
                ClassMethod: wrapFunctionBody,
                ObjectMethod: wrapFunctionBody,
            });
            const out = generator(ast, { retainLines: true, compact: false, comments: true }, code);
            return out.code;
        } catch {
            return code;
        }
    };

    pirates.addHook(
        (code: string) => transform(code),
        { exts: ['.js','.cjs','.mjs','.ts','.tsx'], matcher: (filename: string) => isFromApp(filename), ignoreNodeModules: false }
    );

    logLine('[repro] function-call tracer installed');

    const preloaded = loadedAppFiles.filter(f => !f.startsWith(pkgDir)).slice(0, 5);
    if (preloaded.length) {
        logLine('[repro] tracer installed after some app files were loaded. Move your SDK import earlier so functions inside these files are traced: ' + JSON.stringify(preloaded));
    }
}
installFunctionTracerOnce();

// ===================================================================
// HTTP post helper
// ===================================================================
async function post(apiBase: string, appId: string, appSecret: string, sessionId: string, body: any) {
    try {
        await fetch(`${apiBase}/v1/sessions/${sessionId}/backend`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-App-Id': appId, 'X-App-Secret': appSecret },
            body: JSON.stringify(body),
        });
    } catch {}
}

// -------- helpers
function normalizeRouteKey(method: string, rawPath: string) {
    const base = (rawPath || '/').split('?')[0] || '/';
    return `${String(method || 'GET').toUpperCase()} ${base}`;
}
function coerceBodyToStorable(body: any, contentType?: string | number | string[]) {
    if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
    const ct = Array.isArray(contentType) ? String(contentType[0]) : String(contentType || '');
    const isJson = ct.toLowerCase().includes('application/json');
    try {
        if (Buffer.isBuffer(body)) { const s = body.toString('utf8'); return isJson ? JSON.parse(s) : s; }
        if (typeof body === 'string') return isJson ? JSON.parse(body) : body;
    } catch {
        if (Buffer.isBuffer(body)) return body.toString('utf8');
        if (typeof body === 'string') return body;
    }
    return body;
}

// ===================================================================
// reproMiddleware — captures respBody + per-request call sequence
// ===================================================================
// ===================================================================
// reproMiddleware — captures respBody + per-request call sequence + full trace
// ===================================================================
// ===================================================================
// reproMiddleware — capture respBody + per-request tracer events
// ===================================================================
// ===================================================================
// reproMiddleware — capture respBody + per-request tracer events
// ===================================================================
export function reproMiddleware(cfg: { appId: string; appSecret: string; apiBase: string }) {
    return function (req: Request, res: Response, next: NextFunction) {
        const sid = (req.headers['x-bug-session-id'] as string) || '';
        const aid = (req.headers['x-bug-action-id'] as string) || '';
        if (!sid || !aid) return next();

        const t0 = Date.now();
        const rid = String(t0);
        const url = (req as any).originalUrl || req.url || '/';
        const key = normalizeRouteKey(req.method, url);

        // --- capture response body (unchanged) ---
        let capturedBody: any = undefined;
        const origJson = res.json.bind(res as any);
        (res as any).json = (body: any) => { capturedBody = body; return origJson(body); };
        const origSend = res.send.bind(res as any);
        (res as any).send = (body: any) => {
            if (capturedBody === undefined) capturedBody = coerceBodyToStorable(body, res.getHeader?.('content-type'));
            return origSend(body);
        };
        const origWrite = (res as any).write.bind(res as any);
        const origEnd = (res as any).end.bind(res as any);
        const chunks: Array<Buffer | string> = [];
        (res as any).write = (chunk: any, ...args: any[]) => { try { if (chunk != null) chunks.push(chunk); } catch {} return origWrite(chunk, ...args); };
        (res as any).end = (chunk?: any, ...args: any[]) => { try { if (chunk != null) chunks.push(chunk); } catch {} return origEnd(chunk, ...args); };

        // Keep sid/aid in our ALS (independent of tracer’s ALS)
        als.run({ sid, aid, calls: [] }, () => {
            // Subscribe to tracer events for THIS request's traceId
            const curTid: string | null = typeof tracerPkg.getCurrentTraceId === 'function'
                ? tracerPkg.getCurrentTraceId()
                : null;

            const eventBuf: Array<{ t:number; type:'enter'|'exit'; fn?:string; file?:string; line?:number; depth?:number }> = [];
            let unsubscribe: undefined | (() => void);

            if (curTid && tracerPkg.tracer && typeof tracerPkg.tracer.on === 'function') {
                unsubscribe = tracerPkg.tracer.on((ev: any) => {
                    if (ev && ev.traceId === curTid) {
                        eventBuf.push({ t: ev.t, type: ev.type, fn: ev.fn, file: ev.file, line: ev.line, depth: ev.depth });
                    }
                });
            }

            res.on('finish', () => {
                if (capturedBody === undefined && chunks.length) {
                    const buf = Buffer.isBuffer(chunks[0])
                        ? Buffer.concat(chunks.map(c => (Buffer.isBuffer(c) ? c : Buffer.from(String(c)))))
                        : Buffer.from(chunks.map(String).join(''));
                    capturedBody = coerceBodyToStorable(buf, res.getHeader?.('content-type'));
                }

                // Compact sequence (optional)
                const sequence = eventBuf.filter(e => e.type === 'enter').map(e => e.fn || '');

                // REQUIRED: send full trace as STRING
                let traceStr = '[]';
                try { traceStr = JSON.stringify(eventBuf); } catch {}

                logLine(`[repro] trace sequence ${JSON.stringify({ key, status: res.statusCode, sequence })}`);

                post(cfg.apiBase, cfg.appId, cfg.appSecret, sid, {
                    entries: [{
                        actionId: aid,
                        request: {
                            rid,
                            method: req.method,
                            url,
                            path: url,
                            status: res.statusCode,
                            durMs: Date.now() - t0,
                            headers: {},
                            key,
                            respBody: capturedBody,
                            trace: traceStr,   // <— the tracer data as a STRING
                        },
                        t: Date.now(),
                    }]
                });

                try { unsubscribe && unsubscribe(); } catch {}
            });

            next();
        });
    };
}

// ===================================================================
// Mongo helpers & plugin (unchanged except create wrapper for visibility)
// ===================================================================
function getCollectionNameFromDoc(doc: any): string | undefined {
    const direct =
        doc?.$__?.collection?.collectionName ||
        (doc?.$collection as any)?.collectionName ||
        doc?.collection?.collectionName ||
        (doc?.collection as any)?.name ||
        (doc?.constructor as any)?.collection?.collectionName;
    if (direct) return direct;

    if (doc?.$isSubdocument && typeof (doc as any).ownerDocument === 'function') {
        const parent = (doc as any).ownerDocument();
        return (
            parent?.$__?.collection?.collectionName ||
            (parent?.$collection as any)?.collectionName ||
            parent?.collection?.collectionName ||
            (parent?.collection as any)?.name ||
            (parent?.constructor as any)?.collection?.collectionName
        );
    }
    const ctor = doc?.constructor as any;
    if (ctor?.base && ctor?.base?.collection?.collectionName) {
        return ctor.base.collection.collectionName;
    }
    return undefined;
}
function getCollectionNameFromQuery(q: any): string | undefined {
    return q?.model?.collection?.collectionName || (q?.model?.collection as any)?.name;
}
function resolveCollectionOrWarn(source: any, type: 'doc' | 'query'): string {
    const name = (type === 'doc' ? getCollectionNameFromDoc(source) : getCollectionNameFromQuery(source)) || undefined;
    if (!name) {
        try {
            const modelName =
                type === 'doc'
                    ? (source?.constructor as any)?.modelName || (source?.ownerDocument?.() as any)?.constructor?.modelName
                    : source?.model?.modelName;
            logLine('[repro] could not resolve collection name ' + JSON.stringify({ type, modelName }));
        } catch {}
        return 'unknown';
    }
    return name;
}

export function reproMongoosePlugin(cfg: { appId: string; appSecret: string; apiBase: string }) {
    if (!(mongoose as any).__repro_model_calllog_patched) {
        (mongoose as any).__repro_model_calllog_patched = true;
        const origCreate = (mongoose as any).Model?.create;
        if (origCreate) {
            (mongoose as any).Model.create = async function patchedCreate(this: Model<any>, ...args: any[]) {
                (global as any).__repro_traceEnter('Model.create');
                try { return await origCreate.apply(this, args as any); }
                finally { (global as any).__repro_traceExit(); }
            };
        }
    }

    return function (schema: Schema) {
        schema.pre('save', { document: true }, async function (next) {
            const { sid, aid } = getCtx() as Ctx;
            if (!sid || !aid) return next();
            if ((this as any).$isSubdocument) return next();

            let before: any = null;
            try {
                if (!this.isNew) {
                    const model = this.constructor as Model<any>;
                    before = await model.findById((this as any)._id).lean().exec();
                }
            } catch {}
            (this as any).__repro_meta = { wasNew: this.isNew, before, collection: resolveCollectionOrWarn(this, 'doc') };
            next();
        });

        schema.post('save', { document: true }, function () {
            const { sid, aid } = getCtx() as Ctx;
            if (!sid || !aid) return;
            if ((this as any).$isSubdocument) return;

            const meta = (this as any).__repro_meta || {};
            const before = meta.before ?? null;
            const after = (this as any).toObject({ depopulate: true });
            const collection = meta.collection || resolveCollectionOrWarn(this, 'doc');

            const query = meta.wasNew
                ? { op: 'insertOne', doc: after }
                : { filter: { _id: (this as any)._id }, update: buildMinimalUpdate(before, after), options: { upsert: false } };

            post(cfg.apiBase, cfg.appId, cfg.appSecret, (getCtx() as Ctx).sid!, {
                entries: [{
                    actionId: (getCtx() as Ctx).aid!,
                    db: [{ collection, pk: { _id: (this as any)._id }, before, after, op: meta.wasNew ? 'insert' : 'update', query }],
                    t: Date.now(),
                }]
            });
        });

        schema.pre<Query<any, any>>('findOneAndUpdate', async function (next) {
            const { sid, aid } = getCtx() as Ctx;
            if (!sid || !aid) return next();
            try {
                const filter = (this as any).getFilter();
                const model = (this as any).model as Model<any>;
                (this as any).__repro_before = await model.findOne(filter).lean().exec();
                (this as any).setOptions({ new: true });
                (this as any).__repro_collection = resolveCollectionOrWarn(this, 'query');
            } catch {}
            next();
        });

        schema.post<Query<any, any>>('findOneAndUpdate', function (res: any) {
            const { sid, aid } = getCtx() as Ctx;
            if (!sid || !aid) return;

            const before = (this as any).__repro_before ?? null;
            const after = res ?? null;
            const collection = (this as any).__repro_collection || resolveCollectionOrWarn(this, 'query');
            const pk = after?._id ?? before?._id;

            post(cfg.apiBase, cfg.appId, cfg.appSecret, (getCtx() as Ctx).sid!, {
                entries: [{
                    actionId: (getCtx() as Ctx).aid!,
                    db: [{ collection, pk: { _id: pk }, before, after, op: after && before ? 'update' : after ? 'insert' : 'update' }],
                    t: Date.now()
                }]
            });
        });

        schema.pre<Query<any, any>>('deleteOne', { document: false, query: true }, async function (next) {
            const { sid, aid } = getCtx() as Ctx; if (!sid || !aid) return next();
            try {
                const filter = (this as any).getFilter();
                (this as any).__repro_before = await ((this as any).model as Model<any>).findOne(filter).lean().exec();
                (this as any).__repro_collection = resolveCollectionOrWarn(this, 'query');
                (this as any).__repro_filter = filter;
            } catch {}
            next();
        });

        schema.post<Query<any, any>>('deleteOne', { document: false, query: true }, function () {
            const { sid, aid } = getCtx() as Ctx; if (!sid || !aid) return;
            const before = (this as any).__repro_before ?? null;
            if (!before) return;
            const collection = (this as any).__repro_collection || resolveCollectionOrWarn(this, 'query');
            const filter = (this as any).__repro_filter ?? { _id: before._id };
            post(cfg.apiBase, cfg.appId, cfg.appSecret, (getCtx() as Ctx).sid!, {
                entries: [{
                    actionId: (getCtx() as Ctx).aid!,
                    db: [{ collection, pk: { _id: before._id }, before, after: null, op: 'delete', query: { filter } }],
                    t: Date.now()
                }]
            });
        });

        if (!(mongoose as any).__repro_query_patched) {
            (mongoose as any).__repro_query_patched = true;

            const Q = (mongoose as any).Query?.prototype;
            const Agg = (mongoose as any).Aggregate?.prototype;
            const origExec = Q?.exec;
            const origAggExec = Agg?.exec;

            if (origExec) {
                Q.exec = async function patchedExec(this: any, ...args: any[]) {
                    const { sid, aid } = getCtx() as Ctx;
                    const t0 = Date.now();
                    const collection = this?.model?.collection?.name || 'unknown';
                    const op = String(this?.op || this?.mquery?.op || 'query');
                    const filter = safeJson(this.getFilter?.() ?? this._conditions ?? undefined);
                    const update = safeJson(this.getUpdate?.() ?? this._update ?? undefined);
                    const projection = safeJson(this.projection?.() ?? this._fields ?? undefined);
                    const options = safeJson(this.getOptions?.() ?? this.options ?? undefined);

                    try {
                        const res = await origExec.apply(this, args);
                        const resultMeta = summarizeQueryResult(op, res);
                        if (sid) emitDbQuery(cfg, sid, aid, { collection, op, query: { filter, update, projection, options }, resultMeta, durMs: Date.now() - t0, t: Date.now() });
                        return res;
                    } catch (e: any) {
                        if (sid) emitDbQuery(cfg, sid, aid, { collection, op, query: { filter, update, projection, options }, resultMeta: undefined, durMs: Date.now() - t0, t: Date.now(), error: { message: e?.message, code: e?.code } });
                        throw e;
                    }
                };
            }

            if (origAggExec) {
                Agg.exec = async function patchedAggExec(this: any, ...args: any[]) {
                    const { sid, aid } = getCtx() as Ctx;
                    const t0 = Date.now();
                    const collection = this?.model?.collection?.name || 'unknown';
                    const op = 'aggregate';
                    const pipeline = safeJson(this?.pipeline?.() ?? this?._pipeline ?? this?.pipeline ?? undefined);
                    try {
                        const res = await origAggExec.apply(this, args);
                        const resultMeta = summarizeQueryResult(op, res);
                        if (sid) emitDbQuery(cfg, sid, aid, { collection, op, query: { pipeline }, resultMeta, durMs: Date.now() - t0, t: Date.now() });
                        return res;
                    } catch (e: any) {
                        if (sid) emitDbQuery(cfg, sid, aid, { collection, op, query: { pipeline }, resultMeta: undefined, durMs: Date.now() - t0, t: Date.now(), error: { message: e?.message, code: e?.code } });
                        throw e;
                    }
                };
            }

            const origBulkWrite = (mongoose as any).Model?.bulkWrite;
            if (origBulkWrite) {
                (mongoose as any).Model.bulkWrite = async function patchedBulkWrite(this: Model<any>, ops: any[], options?: any) {
                    const { sid, aid } = getCtx() as Ctx;
                    const t0 = Date.now();
                    const collection = (this as any)?.collection?.name || 'unknown';
                    try {
                        const res = await origBulkWrite.apply(this, [ops, options]);
                        const resultMeta = summarizeBulkResult(res);
                        if (sid) emitDbQuery(cfg, sid, aid, { collection, op: 'bulkWrite', query: { bulk: safeJson(ops), options: safeJson(options) }, resultMeta, durMs: Date.now() - t0, t: Date.now() });
                        return res;
                    } catch (e: any) {
                        if (sid) emitDbQuery(cfg, sid, aid, { collection, op: 'bulkWrite', query: { bulk: safeJson(ops), options: safeJson(options) }, resultMeta: undefined, durMs: Date.now() - t0, t: Date.now(), error: { message: e?.message, code: e?.code } });
                        throw e;
                    }
                };
            }
        }
    };
}

function summarizeQueryResult(op: string, res: any) {
    if (op === 'find' || op === 'findOne' || op === 'aggregate' || op.startsWith('count')) {
        if (Array.isArray(res)) return { docsCount: res.length };
        if (res && typeof res === 'object' && typeof (res as any).toArray === 'function') return { docsCount: undefined };
        if (res == null) return { docsCount: 0 };
        return { docsCount: 1 };
    }
    return pickWriteStats(res);
}
function summarizeBulkResult(res: any) {
    return {
        matched: res?.matchedCount ?? res?.nMatched ?? undefined,
        modified: res?.modifiedCount ?? res?.nModified ?? undefined,
        upserted: res?.upsertedCount ?? undefined,
        deleted: res?.deletedCount ?? undefined,
    };
}
function pickWriteStats(r: any) {
    return {
        matched: r?.matchedCount ?? r?.n ?? r?.nMatched ?? undefined,
        modified: r?.modifiedCount ?? r?.nModified ?? undefined,
        upsertedId: r?.upsertedId ?? r?.upserted?._id ?? undefined,
        deleted: r?.deletedCount ?? undefined,
    };
}
function safeJson(v: any) {
    try { return v == null ? undefined : JSON.parse(JSON.stringify(v)); } catch { return undefined; }
}
function emitDbQuery(cfg: any, sid?: string, aid?: string, payload?: any) {
    if (!sid) return;
    post(cfg.apiBase, cfg.appId, cfg.appSecret, sid, {
        entries: [{
            actionId: aid ?? null,
            db: [{
                collection: payload.collection,
                op: payload.op,
                query: payload.query ?? undefined,
                resultMeta: payload.resultMeta ?? undefined,
                durMs: payload.durMs ?? undefined,
                pk: null, before: null, after: null,
                error: payload.error ?? undefined,
            }],
            t: payload.t,
        }]
    });
}
function buildMinimalUpdate(before: any, after: any) {
    const set: Record<string, any> = {};
    const unset: Record<string, any> = {};
    function walk(b: any, a: any, pathKey = '') {
        const bKeys = b ? Object.keys(b) : [];
        const aKeys = a ? Object.keys(a) : [];
        const all = new Set([...bKeys, ...aKeys]);
        for (const k of all) {
            const p = pathKey ? `${pathKey}.${k}` : k;
            const bv = b?.[k];
            const av = a?.[k];
            const bothObj = bv && av && typeof bv === 'object' && typeof av === 'object' && !Array.isArray(bv) && !Array.isArray(av);
            if (bothObj) { walk(bv, av, p); }
            else if (typeof av === 'undefined') { unset[p] = ''; }
            else if (JSON.stringify(bv) !== JSON.stringify(av)) { set[p] = av; }
        }
    }
    walk(before || {}, after || {});
    const update: any = {};
    if (Object.keys(set).length) update.$set = set;
    if (Object.keys(unset).length) update.$unset = unset;
    return update;
}

// ===================================================================
// SendGrid patch (unchanged)
// ===================================================================
export type SendgridPatchConfig = {
    appId: string;
    appSecret: string;
    apiBase: string,
    resolveContext?: () => { sid?: string; aid?: string } | undefined;
};
export function patchSendgridMail(cfg: SendgridPatchConfig) {
    let sgMail: any;
    try { sgMail = require('@sendgrid/mail'); } catch { return; }

    if (!sgMail || (sgMail as any).__repro_patched) return;
    (sgMail as any).__repro_patched = true;

    const origSend = sgMail.send?.bind(sgMail);
    const origSendMultiple = sgMail.sendMultiple?.bind(sgMail);

    if (origSend) {
        sgMail.send = async function patchedSend(msg: any, isMultiple?: boolean) {
            const t0 = Date.now(); let statusCode: number | undefined; let headers: Record<string, any> | undefined;
            try { const res = await origSend(msg, isMultiple); const r = Array.isArray(res) ? res[0] : res; statusCode = r?.statusCode ?? r?.status; headers = r?.headers ?? undefined; return res; }
            finally { fireCapture('send', msg, t0, statusCode, headers); }
        };
    }
    if (origSendMultiple) {
        sgMail.sendMultiple = async function patchedSendMultiple(msg: any) {
            const t0 = Date.now(); let statusCode: number | undefined; let headers: Record<string, any> | undefined;
            try { const res = await origSendMultiple(msg); const r = Array.isArray(res) ? res[0] : res; statusCode = r?.statusCode ?? r?.status; headers = r?.headers ?? undefined; return res; }
            finally { fireCapture('sendMultiple', msg, t0, statusCode, headers); }
        };
    }

    function fireCapture(kind: 'send' | 'sendMultiple', rawMsg: any, t0: number, statusCode?: number, headers?: any) {
        const ctx = getCtx() as Ctx;
        const sid = ctx.sid ?? cfg.resolveContext?.()?.sid;
        const aid = ctx.aid ?? cfg.resolveContext?.()?.aid;
        if (!sid) return;

        const norm = normalizeSendgridMessage(rawMsg);
        post(cfg.apiBase, cfg.appId, cfg.appSecret, sid, {
            entries: [{
                actionId: aid ?? null,
                email: {
                    provider: 'sendgrid',
                    kind,
                    to: norm.to, cc: norm.cc, bcc: norm.bcc, from: norm.from,
                    subject: norm.subject, text: norm.text, html: norm.html,
                    templateId: norm.templateId, dynamicTemplateData: norm.dynamicTemplateData,
                    categories: norm.categories, customArgs: norm.customArgs,
                    attachmentsMeta: norm.attachmentsMeta,
                    statusCode, durMs: Date.now() - t0, headers: headers ?? {},
                },
                t: Date.now(),
            }]
        });
    }

    function normalizeAddress(a: any): { email: string; name?: string } | null {
        if (!a) return null;
        if (typeof a === 'string') return { email: a };
        if (typeof a === 'object' && a.email) return { email: String(a.email), name: a.name ? String(a.name) : undefined };
        return null;
    }
    function normalizeAddressList(v: any) {
        if (!v) return undefined;
        const arr = Array.isArray(v) ? v : [v];
        const out = arr.map(normalizeAddress).filter(Boolean) as Array<{ email: string; name?: string }>;
        return out.length ? out : undefined;
    }
    function normalizeSendgridMessage(msg: any) {
        const base: any = {
            from: normalizeAddress(msg?.from) ?? undefined,
            to: normalizeAddressList(msg?.to),
            cc: normalizeAddressList(msg?.cc),
            bcc: normalizeAddressList(msg?.bcc),
            subject: msg?.subject ? String(msg.subject) : undefined,
            text: typeof msg?.text === 'string' ? msg.text : undefined,
            html: typeof msg?.html === 'string' ? msg.html : undefined,
            templateId: msg?.templateId ? String(msg.templateId) : undefined,
            dynamicTemplateData: msg?.dynamic_template_data ?? msg?.dynamicTemplateData ?? undefined,
            categories: Array.isArray(msg?.categories) ? msg?.categories.map(String) : undefined,
            customArgs: msg?.customArgs ?? msg?.custom_args ?? undefined,
            attachmentsMeta: Array.isArray(msg?.attachments)
                ? msg.attachments.map((a: any) => ({
                    filename: a?.filename ? String(a.filename) : undefined,
                    type: a?.type ? String(a.type) : undefined,
                    size: a?.content ? byteLen(a.content) : undefined,
                }))
                : undefined,
        };
        const p0 = Array.isArray(msg?.personalizations) ? msg.personalizations[0] : undefined;
        if (p0) {
            base.to = normalizeAddressList(p0.to) ?? base.to;
            base.cc = normalizeAddressList(p0.cc) ?? base.cc;
            base.bcc = normalizeAddressList(p0.bcc) ?? base.bcc;
            if (!base.subject && p0.subject) base.subject = String(p0.subject);
            if (!base.dynamicTemplateData && (p0 as any).dynamic_template_data) base.dynamicTemplateData = (p0 as any).dynamic_template_data;
            if (!base.customArgs && (p0 as any).custom_args) base.customArgs = (p0 as any).custom_args;
        }
        return base;
    }
    function byteLen(content: any): number | undefined {
        try {
            if (typeof content === 'string') return Buffer.byteLength(content, 'utf8');
            if (content && typeof content === 'object' && 'length' in content) return Number((content as any).length);
        } catch {}
        return undefined;
    }
}
