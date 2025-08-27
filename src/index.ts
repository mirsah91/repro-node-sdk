import type { Request, Response, NextFunction } from 'express';
import type { Schema, Model, Query } from 'mongoose';
import * as mongoose from 'mongoose';
import { AsyncLocalStorage } from 'async_hooks';

type Ctx = { sid?: string; aid?: string };
const als = new AsyncLocalStorage<Ctx>();
const getCtx = () => als.getStore() || {};

function getCollectionNameFromDoc(doc: any): string | undefined {
    // Prefer internal collection (Mongoose 8)
    const direct =
        doc?.$__?.collection?.collectionName ||
        (doc?.$collection as any)?.collectionName ||
        doc?.collection?.collectionName ||
        (doc?.collection as any)?.name ||
        (doc?.constructor as any)?.collection?.collectionName;

    if (direct) return direct;

    // Subdocument? Try ownerDocument()
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

    // Discriminator child may have baseModelName
    const ctor = doc?.constructor as any;
    if (ctor?.base && ctor?.base?.collection?.collectionName) {
        return ctor.base.collection.collectionName;
    }

    return undefined;
}

function getCollectionNameFromQuery(q: any): string | undefined {
    return (
        q?.model?.collection?.collectionName ||
        (q?.model?.collection as any)?.name
    );
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
        // PRE: save
        schema.pre('save', { document: true }, async function (next) {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return next();

            // Skip embedded subdocuments — they don't have their own collection
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

        // POST: save
        schema.post('save', { document: true }, function () {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return;

            // Skip embedded subdocuments
            if ((this as any).$isSubdocument) return;

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

        if (!(mongoose as any).__repro_query_patched) {
            (mongoose as any).__repro_query_patched = true;

            const Q = (mongoose as any).Query?.prototype;
            const Agg = (mongoose as any).Aggregate?.prototype;
            const origExec = Q?.exec;
            const origAggExec = Agg?.exec;

            // Patch Query.exec for all model ops (find, findOne, update*, delete*, count*, etc.)
            if (origExec) {
                Q.exec = async function patchedExec(this: any, ...args: any[]) {
                    const { sid, aid } = getCtx();
                    const t0 = Date.now();
                    let error: any = null;

                    // gather query facts up front
                    const collection = this?.model?.collection?.name || 'unknown';
                    const op = String(this?.op || this?.mquery?.op || 'query');
                    const filter = safeJson(this.getFilter?.() ?? this._conditions ?? undefined);
                    const update = safeJson(this.getUpdate?.() ?? this._update ?? undefined);
                    const projection = safeJson(this.projection?.() ?? this._fields ?? undefined);
                    const options = safeJson(this.getOptions?.() ?? this.options ?? undefined);

                    try {
                        const res = await origExec.apply(this, args);
                        // summarize result (don’t serialize large docs)
                        const resultMeta = summarizeQueryResult(op, res);
                        if (sid) emitDbQuery(cfg, sid, aid, {
                            collection, op,
                            query: { filter, update, projection, options },
                            resultMeta,
                            durMs: Date.now() - t0,
                            t: Date.now(),
                        });
                        return res;
                    } catch (e: any) {
                        error = { message: e?.message, code: e?.code };
                        if (sid) emitDbQuery(cfg, sid, aid, {
                            collection, op,
                            query: { filter, update, projection, options },
                            resultMeta: undefined,
                            durMs: Date.now() - t0,
                            t: Date.now(),
                            error,
                        });
                        throw e;
                    }
                };
            }

            // Patch Aggregate.exec
            if (origAggExec) {
                Agg.exec = async function patchedAggExec(this: any, ...args: any[]) {
                    const { sid, aid } = getCtx();
                    const t0 = Date.now();
                    const collection = this?.model?.collection?.name || 'unknown';
                    const op = 'aggregate';
                    const pipeline = safeJson(this?.pipeline?.() ?? this?._pipeline ?? this?.pipeline ?? undefined);
                    try {
                        const res = await origAggExec.apply(this, args);
                        const resultMeta = summarizeQueryResult(op, res);
                        if (sid) emitDbQuery(cfg, sid, aid, {
                            collection, op,
                            query: { pipeline },
                            resultMeta,
                            durMs: Date.now() - t0,
                            t: Date.now(),
                        });
                        return res;
                    } catch (e: any) {
                        const error = { message: e?.message, code: e?.code };
                        if (sid) emitDbQuery(cfg, sid, aid, {
                            collection, op,
                            query: { pipeline },
                            resultMeta: undefined,
                            durMs: Date.now() - t0,
                            t: Date.now(),
                            error,
                        });
                        throw e;
                    }
                };
            }

            // Patch Model.bulkWrite
            const origBulkWrite = (mongoose as any).Model?.bulkWrite;
            if (origBulkWrite) {
                (mongoose as any).Model.bulkWrite = async function patchedBulkWrite(this: Model<any>, ops: any[], options?: any) {
                    const { sid, aid } = getCtx();
                    const t0 = Date.now();
                    const collection = (this as any)?.collection?.name || 'unknown';
                    try {
                        const res = await origBulkWrite.apply(this, [ops, options]);
                        const resultMeta = summarizeBulkResult(res);
                        if (sid) emitDbQuery(cfg, sid, aid, {
                            collection, op: 'bulkWrite',
                            query: { bulk: safeJson(ops), options: safeJson(options) },
                            resultMeta,
                            durMs: Date.now() - t0,
                            t: Date.now(),
                        });
                        return res;
                    } catch (e: any) {
                        const error = { message: e?.message, code: e?.code };
                        if (sid) emitDbQuery(cfg, sid, aid, {
                            collection, op: 'bulkWrite',
                            query: { bulk: safeJson(ops), options: safeJson(options) },
                            resultMeta: undefined,
                            durMs: Date.now() - t0,
                            t: Date.now(),
                            error,
                        });
                        throw e;
                    }
                };
            }
        }
    };
}

function summarizeQueryResult(op: string, res: any) {
    // reads
    if (op === 'find' || op === 'findOne' || op === 'aggregate' || op.startsWith('count')) {
        if (Array.isArray(res)) return { docsCount: res.length };
        if (res && typeof res === 'object' && typeof res.toArray === 'function') return { docsCount: undefined };
        if (res == null) return { docsCount: 0 };
        return { docsCount: 1 };
    }
    // writes
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
                // New fields; server will accept them
                query: payload.query ?? undefined,
                resultMeta: payload.resultMeta ?? undefined,
                durMs: payload.durMs ?? undefined,
                // keep document-diff fields null for pure queries
                pk: null, before: null, after: null,
                error: payload.error ?? undefined,
            }],
            t: payload.t,
        }]
    });
}

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
            if (!base.dynamicTemplateData && p0.dynamic_template_data) base.dynamicTemplateData = p0.dynamic_template_data;
            if (!base.customArgs && p0.custom_args) base.customArgs = p0.custom_args;
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
