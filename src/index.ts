import type { Request, Response, NextFunction } from 'express';
import type { Schema, Model, Query } from 'mongoose';
import * as mongoose from 'mongoose';
import { AsyncLocalStorage } from 'async_hooks';

/**
 * ============================= IMPORTANT =============================
 * We snapshot Mongoose core methods BEFORE tracer init, then re-apply them
 * AFTER tracer init. This guarantees Model.find() still returns a Query and
 * chainability (e.g., .sort().lean()) is preserved. No behavior changes.
 * =====================================================================
 */
const __ORIG = (() => {
    const M: any = (mongoose as any).Model;
    const Qp: any = (mongoose as any).Query?.prototype;
    const Ap: any = (mongoose as any).Aggregate?.prototype;
    return {
        Model: {
            find: M?.find,
            findOne: M?.findOne,
            findById: M?.findById,
            create: M?.create,
            insertMany: M?.insertMany,
            updateOne: M?.updateOne,
            updateMany: M?.updateMany,
            replaceOne: M?.replaceOne,
            deleteOne: M?.deleteOne,
            deleteMany: M?.deleteMany,
            countDocuments: M?.countDocuments,
            estimatedDocumentCount: M?.estimatedDocumentCount,
            distinct: M?.distinct,
            findOneAndUpdate: M?.findOneAndUpdate,
            findOneAndDelete: M?.findOneAndDelete,
            findOneAndReplace: M?.findOneAndReplace,
            findOneAndRemove: M?.findOneAndRemove,
            bulkWrite: M?.bulkWrite,
        },
        Query: {
            exec: Qp?.exec,
            lean: Qp?.lean,
            sort: Qp?.sort,
            select: Qp?.select,
            limit: Qp?.limit,
            skip: Qp?.skip,
            populate: Qp?.populate,
            getFilter: Qp?.getFilter,
            getUpdate: Qp?.getUpdate,
            getOptions: Qp?.getOptions,
            projection: Qp?.projection,
        },
        Aggregate: {
            exec: Ap?.exec,
        }
    };
})();

function restoreMongooseIfNeeded() {
    try {
        const M: any = (mongoose as any).Model;
        const Qp: any = (mongoose as any).Query?.prototype;
        const Ap: any = (mongoose as any).Aggregate?.prototype;
        const safeSet = (obj: any, key: string, val: any) => {
            if (!obj || !val) return;
            if (obj[key] !== val) { try { obj[key] = val; } catch {} }
        };

        // Restore Model methods (chainability depends on these returning Query)
        Object.entries(__ORIG.Model).forEach(([k, v]) => safeSet(M, k, v));

        // Restore Query prototype essentials (exec/lean/etc.)
        Object.entries(__ORIG.Query).forEach(([k, v]) => safeSet(Qp, k, v));

        // Restore Aggregate exec
        Object.entries(__ORIG.Aggregate).forEach(([k, v]) => safeSet(Ap, k, v));
    } catch {}
}

// ====== tiny, safe tracer auto-init (no node_modules patches) ======
type TracerApi = {
    init?: (opts: any) => void;
    tracer?: { on: (fn: (ev: any) => void) => () => void };
    getCurrentTraceId?: () => string | null;
    patchHttp?: () => void; // optional in your tracer
};

function escapeRx(s: string) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
let __TRACER__: TracerApi | null = null;
let __TRACER_READY = false;

// (function ensureTracerAutoInit() {
//     if (__TRACER_READY) return;
//
//     try {
//         const tracerPkg: TracerApi = require('../tracer');
//
//         const cwd = process.cwd().replace(/\\/g, '/');
//         const sdkRoot = __dirname.replace(/\\/g, '/');
//
//         // include ONLY app code (no node_modules) to avoid interfering with deps
//         const include = [ new RegExp('^' + escapeRx(cwd) + '/(?!node_modules/)') ];
//
//         // additionally exclude common model/schema folders to be extra safe
//         const extraExcludes = [
//             '/model/', '/models/', '/schema/', '/schemas/', '/db/', '/database/', '/mongo/', '/repositories?/'
//         ].map(seg => new RegExp(escapeRx(cwd) + '.*' + seg));
//
//         // exclude this SDK itself (and any babel internals if present)
//         const exclude = [
//             new RegExp('^' + escapeRx(sdkRoot) + '/'),
//             /node_modules[\\/]@babel[\\/].*/,
//             ...extraExcludes,
//         ];
//
//         tracerPkg.init?.({
//             instrument: true,               // tracer can instrument app code
//             include,
//             exclude,                        // but never our SDK or common data/model paths
//             mode: process.env.TRACE_MODE || 'v8',
//             samplingMs: 10,
//         });
//
//         tracerPkg.patchHttp?.();
//
//         __TRACER__ = tracerPkg;
//         __TRACER_READY = true;
//     } catch {
//         __TRACER__ = null; // optional tracer
//     } finally {
//         // Critical: make sure Mongoose core is pristine after tracer init.
//         restoreMongooseIfNeeded();
//         // And again on next tick (if tracer defers some wrapping)
//         setImmediate(restoreMongooseIfNeeded);
//     }
// })();
// ===================================================================

// ===== Configurable tracer init (explicit, no auto-run) =====
type TracerInitOpts = {
    instrument?: boolean;
    include?: RegExp[];
    exclude?: RegExp[];
    mode?: string;
    samplingMs?: number;
};

function defaultTracerInitOpts(): TracerInitOpts {
    const cwd = process.cwd().replace(/\\/g, '/');
    const sdkRoot = __dirname.replace(/\\/g, '/');
    const escapeRx = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    const include = [ new RegExp('^' + escapeRx(cwd) + '/(?!node_modules/)') ];
    const extraExcludes = [
        '/model/', '/models/', '/schema/', '/schemas/', '/db/', '/database/', '/mongo/', '/repositories?/'
    ].map(seg => new RegExp(escapeRx(cwd) + '.*' + seg));

    const exclude = [
        new RegExp('^' + escapeRx(sdkRoot) + '/'), // never instrument the SDK itself
        /node_modules[\\/]@babel[\\/].*/,
        ...extraExcludes,
    ];

    return {
        instrument: true,
        include,
        exclude,
        mode: process.env.TRACE_MODE || 'v8',
        samplingMs: 10,
    };
}

/** Call this from the client app to enable tracing. Safe to call multiple times. */
export function initReproTracing(opts?: TracerInitOpts) {
    if (__TRACER_READY) return __TRACER__;
    try {
        const tracerPkg: TracerApi = require('../tracer');
        const initOpts = { ...defaultTracerInitOpts(), ...(opts || {}) };
        tracerPkg.init?.(initOpts);
        tracerPkg.patchHttp?.();
        __TRACER__ = tracerPkg;
        __TRACER_READY = true;
    } catch {
        __TRACER__ = null; // SDK still works without tracer
    } finally {
        // keep Mongoose prototypes pristine in either case
        restoreMongooseIfNeeded();
        setImmediate(restoreMongooseIfNeeded);
    }
    return __TRACER__;
}

/** Optional helper if users want to check it. */
export function isReproTracingEnabled() { return __TRACER_READY; }

type Ctx = { sid?: string; aid?: string };
const als = new AsyncLocalStorage<Ctx>();
const getCtx = () => als.getStore() || {};

function getCollectionNameFromDoc(doc: any): string | undefined {
    const direct =
        doc?.$__?.collection?.collectionName ||
        (doc?.$collection as any)?.collectionName ||
        doc?.collection?.collectionName ||
        (doc?.collection as any)?.name ||
        (doc?.constructor as any)?.collection?.collectionName;

    if (direct) return direct;

    if (doc?.$isSubdocument && typeof doc.ownerDocument === 'function') {
        const parent = doc.ownerDocument();
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
    const name =
        (type === 'doc'
            ? getCollectionNameFromDoc(source)
            : getCollectionNameFromQuery(source)) || undefined;

    if (!name) {
        try {
            const modelName =
                type === 'doc'
                    ? (source?.constructor as any)?.modelName ||
                    (source?.ownerDocument?.() as any)?.constructor?.modelName
                    : source?.model?.modelName;
            // eslint-disable-next-line no-console
            console.warn('[repro] could not resolve collection name', { type, modelName });
        } catch {}
        return 'unknown';
    }
    return name;
}

async function post(apiBase: string, appId: string, appSecret: string, sessionId: string, body: any) {
    try {
        await fetch(`${apiBase}/v1/sessions/${sessionId}/backend`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-App-Id': appId, 'X-App-Secret': appSecret },
            body: JSON.stringify(body),
        });
    } catch { /* swallow in SDK */ }
}

// -------- helpers for response capture & grouping --------
function normalizeRouteKey(method: string, rawPath: string) {
    const base = (rawPath || '/').split('?')[0] || '/';
    return `${String(method || 'GET').toUpperCase()} ${base}`;
}

function coerceBodyToStorable(body: any, contentType?: string | number | string[]) {
    if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;

    const ct = Array.isArray(contentType) ? String(contentType[0]) : String(contentType || '');
    const isLikelyJson = ct.toLowerCase().includes('application/json');

    try {
        if (Buffer.isBuffer(body)) {
            const s = body.toString('utf8');
            return isLikelyJson ? JSON.parse(s) : s;
        }
        if (typeof body === 'string') {
            return isLikelyJson ? JSON.parse(body) : body;
        }
    } catch {
        if (Buffer.isBuffer(body)) return body.toString('utf8');
        if (typeof body === 'string') return body;
    }
    return body;
}

// ===================================================================
// reproMiddleware — unchanged behavior + passive per-request trace
// ===================================================================
export function reproMiddleware(cfg: { appId: string; appSecret: string; apiBase: string }) {
    return function (req: Request, res: Response, next: NextFunction) {
        const sid = (req.headers['x-bug-session-id'] as string) || '';
        const aid = (req.headers['x-bug-action-id'] as string) || '';
        if (!sid || !aid) return next(); // only capture tagged requests

        const t0 = Date.now();
        const rid = String(t0);
        const url = (req as any).originalUrl || req.url || '/';
        const path = url; // back-compat
        const key = normalizeRouteKey(req.method, url);

        // ---- response body capture (unchanged) ----
        let capturedBody: any = undefined;
        const origJson = res.json.bind(res as any);
        (res as any).json = (body: any) => { capturedBody = body; return origJson(body); };

        const origSend = res.send.bind(res as any);
        (res as any).send = (body: any) => {
            if (capturedBody === undefined) {
                capturedBody = coerceBodyToStorable(body, res.getHeader?.('content-type'));
            }
            return origSend(body);
        };

        const origWrite = (res as any).write.bind(res as any);
        const origEnd = (res as any).end.bind(res as any);
        const chunks: Array<Buffer | string> = [];
        (res as any).write = (chunk: any, ...args: any[]) => { try { if (chunk != null) chunks.push(chunk); } catch {} return origWrite(chunk, ...args); };
        (res as any).end = (chunk?: any, ...args: any[]) => { try { if (chunk != null) chunks.push(chunk); } catch {} return origEnd(chunk, ...args); };

        // ---- our ALS (unchanged) ----
        als.run({ sid, aid }, () => {
            // subscribe to tracer for this request (passive only)
            const events: Array<{ t:number; type:'enter'|'exit'; fn?:string; file?:string; line?:number; depth?:number }> = [];
            let unsubscribe: undefined | (() => void);

            try {
                if (__TRACER__?.tracer?.on) {
                    const getTid = __TRACER__?.getCurrentTraceId;
                    const tidNow = getTid ? getTid() : null;

                    if (tidNow) {
                        unsubscribe = __TRACER__.tracer.on((ev: any) => {
                            if (ev && ev.traceId === tidNow) {
                                events.push({
                                    t: ev.t, type: ev.type, fn: ev.fn, file: ev.file, line: ev.line, depth: ev.depth
                                });
                            }
                        });
                    }
                }
            } catch { /* never break user code */ }

            res.on('finish', () => {
                if (capturedBody === undefined && chunks.length) {
                    const buf = Buffer.isBuffer(chunks[0])
                        ? Buffer.concat(chunks.map(c => (Buffer.isBuffer(c) ? c : Buffer.from(String(c)))))
                        : Buffer.from(chunks.map(String).join(''));
                    capturedBody = coerceBodyToStorable(buf, res.getHeader?.('content-type'));
                }

                let traceStr = '[]';
                try { traceStr = JSON.stringify(events); } catch {}

                post(cfg.apiBase, cfg.appId, cfg.appSecret, sid, {
                    entries: [{
                        actionId: aid,
                        request: {
                            rid,
                            method: req.method,
                            url,
                            path,
                            status: res.statusCode,
                            durMs: Date.now() - t0,
                            headers: {},
                            key,
                            respBody: capturedBody,
                            trace: traceStr,
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
// reproMongoosePlugin — stable + NON-intrusive query logs
//   - NO prototype monkey-patching of Mongoose
//   - ONLY schema middleware (pre/post) for specific ops
//   - keeps your existing doc-diff hooks
// ===================================================================
export function reproMongoosePlugin(cfg: { appId: string; appSecret: string; apiBase: string }) {
    return function (schema: Schema) {
        // -------- pre/post save (unchanged) --------
        schema.pre('save', { document: true }, async function (next) {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return next();
            if ((this as any).$isSubdocument) return next();

            let before: any = null;
            try {
                if (!this.isNew) {
                    const model = this.constructor as Model<any>;
                    before = await model.findById(this._id).lean().exec();
                }
            } catch {}
            (this as any).__repro_meta = {
                wasNew: this.isNew,
                before,
                collection: resolveCollectionOrWarn(this, 'doc'),
            };
            next();
        });

        schema.post('save', { document: true }, function () {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return;
            if ((this as any).$isSubdocument) return;

            const meta = (this as any).__repro_meta || {};
            const before = meta.before ?? null;
            const after = this.toObject({ depopulate: true });
            const collection = meta.collection || resolveCollectionOrWarn(this, 'doc');

            const query = meta.wasNew
                ? { op: 'insertOne', doc: after }
                : { filter: { _id: this._id }, update: buildMinimalUpdate(before, after), options: { upsert: false } };

            post(cfg.apiBase, cfg.appId, cfg.appSecret, (getCtx() as Ctx).sid!, {
                entries: [{
                    actionId: (getCtx() as Ctx).aid!,
                    db: [{ collection, pk: { _id: (this as any)._id }, before, after, op: meta.wasNew ? 'insert' : 'update', query }],
                    t: Date.now(),
                }]
            });
        });

        // -------- findOneAndUpdate capture (unchanged) --------
        schema.pre<Query<any, any>>('findOneAndUpdate', async function (next) {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return next();
            try {
                const filter = this.getFilter();
                const model = this.model as Model<any>;
                (this as any).__repro_before = await model.findOne(filter).lean().exec();
                this.setOptions({ new: true });
                (this as any).__repro_collection = resolveCollectionOrWarn(this, 'query');
            } catch {}
            next();
        });

        schema.post<Query<any, any>>('findOneAndUpdate', function (res: any) {
            const { sid, aid } = getCtx();
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

        // -------- deleteOne capture (unchanged) --------
        schema.pre<Query<any, any>>('deleteOne', { document: false, query: true }, async function (next) {
            const { sid, aid } = getCtx(); if (!sid || !aid) return next();
            try {
                const filter = this.getFilter();
                (this as any).__repro_before = await (this.model as Model<any>).findOne(filter).lean().exec();
                (this as any).__repro_collection = resolveCollectionOrWarn(this, 'query');
                (this as any).__repro_filter = filter;
            } catch {}
            next();
        });

        schema.post<Query<any, any>>('deleteOne', { document: false, query: true }, function () {
            const { sid, aid } = getCtx(); if (!sid || !aid) return;
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

        // -------- NON-intrusive generic query telemetry via schema hooks -------
        const READ_OPS = [
            'find',
            'findOne',
            'countDocuments',
            'estimatedDocumentCount',
            'distinct',
        ] as const;

        const WRITE_OPS = [
            'updateOne',
            'updateMany',
            'replaceOne',
            'deleteMany',
            'findOneAndUpdate'
        ] as const;

        function attachQueryHooks(op: string) {
            schema.pre(op as any, function (this: any, next: Function) {
                try {
                    (this as any).__repro_qmeta = {
                        t0: Date.now(),
                        collection: this?.model?.collection?.name || 'unknown',
                        op,
                        filter: safeJson(this.getFilter?.() ?? this._conditions ?? undefined),
                        update: safeJson(this.getUpdate?.() ?? this._update ?? undefined),
                        projection: safeJson(this.projection?.() ?? this._fields ?? undefined),
                        options: safeJson(this.getOptions?.() ?? this.options ?? undefined),
                    };
                } catch {
                    (this as any).__repro_qmeta = { t0: Date.now(), collection: 'unknown', op };
                }
                next();
            });

            schema.post(op as any, function (this: any, res: any) {
                const { sid, aid } = getCtx();
                if (!sid) return;

                const meta = (this as any).__repro_qmeta || { t0: Date.now(), collection: 'unknown', op };
                const resultMeta = summarizeQueryResult(op, res);

                emitDbQuery(cfg, sid, aid, {
                    collection: meta.collection,
                    op,
                    query: { filter: meta.filter, update: meta.update, projection: meta.projection, options: meta.options },
                    resultMeta,
                    durMs: Date.now() - meta.t0,
                    t: Date.now(),
                });
            });
        }

        READ_OPS.forEach(attachQueryHooks);
        WRITE_OPS.forEach(attachQueryHooks);

        // Aggregate middleware (non-intrusive)
        schema.pre('aggregate', function (this: any, next: Function) {
            try {
                (this as any).__repro_aggmeta = {
                    t0: Date.now(),
                    collection:
                        this?.model?.collection?.name ||
                        this?._model?.collection?.name ||
                        (this?.model && this.model.collection?.name) ||
                        'unknown',
                    pipeline: safeJson(this.pipeline?.() ?? this._pipeline ?? undefined),
                };
            } catch {
                (this as any).__repro_aggmeta = { t0: Date.now(), collection: 'unknown', pipeline: undefined };
            }
            next();
        });

        schema.post('aggregate', function (this: any, res: any[]) {
            const { sid, aid } = getCtx();
            if (!sid) return;

            const meta = (this as any).__repro_aggmeta || { t0: Date.now(), collection: 'unknown' };
            const resultMeta = summarizeQueryResult('aggregate', res);

            emitDbQuery(cfg, sid, aid, {
                collection: meta.collection,
                op: 'aggregate',
                query: { pipeline: meta.pipeline },
                resultMeta,
                durMs: Date.now() - meta.t0,
                t: Date.now(),
            });
        });
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

    function walk(b: any, a: any, path = '') {
        const bKeys = b ? Object.keys(b) : [];
        const aKeys = a ? Object.keys(a) : [];
        const all = new Set([...bKeys, ...aKeys]);
        for (const k of all) {
            const p = path ? `${path}.${k}` : k;
            const bv = b?.[k];
            const av = a?.[k];

            const bothObj =
                bv && av &&
                typeof bv === 'object' &&
                typeof av === 'object' &&
                !Array.isArray(bv) &&
                !Array.isArray(av);

            if (bothObj) {
                walk(bv, av, p);
            } else if (typeof av === 'undefined') {
                unset[p] = '';
            } else if (JSON.stringify(bv) !== JSON.stringify(av)) {
                set[p] = av;
            }
        }
    }

    walk(before || {}, after || {});
    const update: any = {};
    if (Object.keys(set).length) update.$set = set;
    if (Object.keys(unset).length) update.$unset = unset;
    return update;
}

// ===================================================================
// Sendgrid — unchanged
// ===================================================================
export type SendgridPatchConfig = {
    appId: string;
    appSecret: string;
    apiBase: string;
    resolveContext?: () => { sid?: string; aid?: string } | undefined;
};

export function patchSendgridMail(cfg: SendgridPatchConfig) {
    let sgMail: any;
    try { sgMail = require('@sendgrid/mail'); } catch { return; } // no-op if not installed

    if (!sgMail || (sgMail as any).__repro_patched) return;
    (sgMail as any).__repro_patched = true;

    const origSend = sgMail.send?.bind(sgMail);
    const origSendMultiple = sgMail.sendMultiple?.bind(sgMail);

    if (origSend) {
        sgMail.send = async function patchedSend(msg: any, isMultiple?: boolean) {
            const t0 = Date.now();
            let statusCode: number | undefined;
            let headers: Record<string, any> | undefined;
            try {
                const res = await origSend(msg, isMultiple);
                const r = Array.isArray(res) ? res[0] : res;
                statusCode = r?.statusCode ?? r?.status;
                headers = r?.headers ?? undefined;
                return res;
            } finally {
                fireCapture('send', msg, t0, statusCode, headers);
            }
        };
    }

    if (origSendMultiple) {
        sgMail.sendMultiple = async function patchedSendMultiple(msg: any) {
            const t0 = Date.now();
            let statusCode: number | undefined;
            let headers: Record<string, any> | undefined;
            try {
                const res = await origSendMultiple(msg);
                const r = Array.isArray(res) ? res[0] : res;
                statusCode = r?.statusCode ?? r?.status;
                headers = r?.headers ?? undefined;
                return res;
            } finally {
                fireCapture('sendMultiple', msg, t0, statusCode, headers);
            }
        };
    }

    function fireCapture(kind: 'send' | 'sendMultiple', rawMsg: any, t0: number, statusCode?: number, headers?: any) {
        const ctx = getCtx();
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
        const base = {
            from: normalizeAddress(msg?.from) ?? undefined,
            to: normalizeAddressList(msg?.to),
            cc: normalizeAddressList(msg?.cc),
            bcc: normalizeAddressList(msg?.bcc),
            subject: msg?.subject ? String(msg.subject) : undefined,
            text: typeof msg?.text === 'string' ? msg.text : undefined,
            html: typeof msg?.html === 'string' ? msg.html : undefined,
            templateId: msg?.templateId ? String(msg.templateId) : undefined,
            dynamicTemplateData: msg?.dynamic_template_data ?? msg?.dynamicTemplateData ?? undefined,
            categories: Array.isArray(msg?.categories) ? msg.categories.map(String) : undefined,
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
