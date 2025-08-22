import type { Request, Response, NextFunction } from 'express';
import type { Schema, Model, Query } from 'mongoose';
import { AsyncLocalStorage } from 'async_hooks';

type Ctx = { sid?: string; aid?: string };
const als = new AsyncLocalStorage<Ctx>();
const getCtx = () => als.getStore() || {};

function getCollectionNameFromDoc(doc: any): string | undefined {
    // Most reliable first
    return (
        doc?.$__?.collection?.collectionName ||          // internal collection holder
        (doc?.$collection as any)?.collectionName ||      // alt internal on some versions
        doc?.collection?.collectionName ||                // public API
        (doc?.collection as any)?.name ||                 // old fallback
        (doc?.constructor as any)?.collection?.collectionName // via model constructor
    );
}

function getCollectionNameFromQuery(q: any): string | undefined {
    return (
        q?.model?.collection?.collectionName ||
        (q?.model?.collection as any)?.name
    );
}

function resolveCollectionOrWarn(source: any, type: 'doc'|'query'): string {
    const name =
        (type === 'doc' ? getCollectionNameFromDoc(source) : getCollectionNameFromQuery(source))
        || undefined;

    if (!name) {
        // Optional: emit a low-noise console.warn once to help trace edge models
        try {
            const modelName = type === 'doc'
                ? (source?.constructor as any)?.modelName
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
    // strip query string to stabilize grouping across re-loads
    const base = (rawPath || '/').split('?')[0] || '/';
    return `${String(method || 'GET').toUpperCase()} ${base}`;
}

function coerceBodyToStorable(body: any, contentType?: string | number | string[]) {
    // If already an object/array, store as-is
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
        // fall through to raw string if JSON parse fails
        if (Buffer.isBuffer(body)) return body.toString('utf8');
        if (typeof body === 'string') return body;
    }
    // last resort
    return body;
}

// ===================================================================
// reproMiddleware — now captures respBody (+ key) and posts both url & path
// ===================================================================
export function reproMiddleware(cfg: { appId: string; appSecret: string; apiBase: string }) {
    return function (req: Request, res: Response, next: NextFunction) {
        const sid = (req.headers['x-bug-session-id'] as string) || '';
        const aid = (req.headers['x-bug-action-id'] as string) || '';
        if (!sid || !aid) return next(); // only capture tagged requests

        const t0 = Date.now();
        const rid = String(t0);
        const url = (req as any).originalUrl || req.url || '/'; // send as 'url'
        const path = url;                                       // keep 'path' for back-compat
        const key = normalizeRouteKey(req.method, url);

        // ---- Capture response body robustly (json/send/write/end) ----
        let capturedBody: any = undefined;
        const origJson = res.json.bind(res as any);
        (res as any).json = (body: any) => {
            capturedBody = body;
            return origJson(body);
        };

        const origSend = res.send.bind(res as any);
        (res as any).send = (body: any) => {
            if (capturedBody === undefined) {
                capturedBody = coerceBodyToStorable(body, res.getHeader?.('content-type'));
            }
            return origSend(body);
        };

        // If the handler uses res.write/res.end directly, accumulate chunks
        const origWrite = (res as any).write.bind(res as any);
        const origEnd = (res as any).end.bind(res as any);
        const chunks: Array<Buffer | string> = [];

        (res as any).write = (chunk: any, ...args: any[]) => {
            try { if (chunk != null) chunks.push(chunk); } catch {}
            return origWrite(chunk, ...args);
        };
        (res as any).end = (chunk?: any, ...args: any[]) => {
            try { if (chunk != null) chunks.push(chunk); } catch {}
            return origEnd(chunk, ...args);
        };

        als.run({ sid, aid }, () => {
            res.on('finish', () => {
                // If nothing captured via json/send, try assembled chunks
                if (capturedBody === undefined && chunks.length) {
                    const buf = Buffer.isBuffer(chunks[0])
                        ? Buffer.concat(chunks.map(c => (Buffer.isBuffer(c) ? c : Buffer.from(String(c)))))
                        : Buffer.from(chunks.map(String).join(''));
                    capturedBody = coerceBodyToStorable(buf, res.getHeader?.('content-type'));
                }

                post(cfg.apiBase, cfg.appId, cfg.appSecret, sid, {
                    entries: [{
                        actionId: aid,
                        request: {
                            rid,
                            method: req.method,
                            url,                       // NEW: explicit url (API stores this)
                            path,                      // kept for backward compat
                            status: res.statusCode,
                            durMs: Date.now() - t0,
                            headers: {},               // (optional) sanitize & include if desired
                            key,                       // NEW: e.g. "GET /items"
                            respBody: capturedBody,    // NEW: JSON if parseable, else string
                        },
                        t: Date.now(),
                    }]
                });
            });
            next();
        });
    };
}

// ===================================================================
// reproMongoosePlugin — unchanged logic, light polish
// ===================================================================
export function reproMongoosePlugin(cfg: { appId: string; appSecret: string; apiBase: string }) {
    return function (schema: Schema) {
        // PRE: save — capture before + collection safely
        schema.pre('save', { document: true }, async function (next) {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return next();

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

        // POST: save — use cached before + robust collection name
        schema.post('save', { document: true }, function () {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return;

            const meta = (this as any).__repro_meta || {};
            const before = meta.before ?? null;
            const after = this.toObject({ depopulate: true });
            const collection = meta.collection || resolveCollectionOrWarn(this, 'doc');

            post(cfg.apiBase, cfg.appId, cfg.appSecret, sid!, {
                entries: [{
                    actionId: aid!,
                    db: [{
                        collection,
                        pk: { _id: this._id },
                        before,
                        after,
                        op: meta.wasNew ? 'insert' : 'update',
                    }],
                    t: Date.now(),
                }]
            });
        });

        // PRE: findOneAndUpdate — capture "before"
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

        // POST: findOneAndUpdate — emit change
        schema.post<Query<any, any>>('findOneAndUpdate', function (res: any) {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return;

            const before = (this as any).__repro_before ?? null;
            const after = res ?? null;
            const collection =
                (this as any).__repro_collection || resolveCollectionOrWarn(this, 'query');

            const pk = after?._id ?? before?._id;

            post(cfg.apiBase, cfg.appId, cfg.appSecret, sid!, {
                entries: [{
                    actionId: aid!,
                    db: [{
                        collection,
                        pk: { _id: pk },
                        before,
                        after,
                        op: after && before ? 'update' : after ? 'insert' : 'update',
                    }],
                    t: Date.now()
                }]
            });
        });

        // PRE: deleteOne — capture "before"
        schema.pre<Query<any, any>>('deleteOne', { document: false, query: true }, async function (next) {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return next();
            try {
                const filter = this.getFilter();
                const model = this.model as Model<any>;
                (this as any).__repro_before = await model.findOne(filter).lean().exec();
                (this as any).__repro_collection = resolveCollectionOrWarn(this, 'query');
            } catch {}
            next();
        });

        schema.post<Query<any, any>>('deleteOne', { document: false, query: true }, function () {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return;

            const before = (this as any).__repro_before ?? null;
            if (!before) return;

            const collection =
                (this as any).__repro_collection || resolveCollectionOrWarn(this, 'query');

            post(cfg.apiBase, cfg.appId, cfg.appSecret, sid!, {
                entries: [{
                    actionId: aid!,
                    db: [{
                        collection,
                        pk: { _id: before._id },
                        before,
                        after: null,
                        op: 'delete',
                    }],
                    t: Date.now()
                }]
            });
        });
    };
}
