import type { Request, Response, NextFunction } from 'express';
import type { Schema, Model, Query } from 'mongoose';
import { AsyncLocalStorage } from 'async_hooks';

type Ctx = { sid?: string; aid?: string };
const als = new AsyncLocalStorage<Ctx>();
const getCtx = () => als.getStore() || {};

async function post(apiBase: string, appId: string, appSecret: string, sessionId: string, body: any) {
    try {
        await fetch(`${apiBase}/v1/sessions/${sessionId}/backend`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-App-Id': appId, 'X-App-Secret': appSecret },
            body: JSON.stringify(body),
        }); } catch {}
}

export function reproMiddleware(cfg: { appId: string; appSecret: string; apiBase: string }) {
    return function (req: Request, res: Response, next: NextFunction) {
        const sid = (req.headers['x-bug-session-id'] as string) || '';
        const aid = (req.headers['x-bug-action-id'] as string) || '';
        if (!sid || !aid) return next();

        const t0 = Date.now();
        als.run({ sid, aid }, () => {
            res.on('finish', () => {
                post(cfg.apiBase, cfg.appId, cfg.appSecret, sid, {
                    entries: [{
                        actionId: aid,
                        request: {
                            rid: String(t0),
                            method: req.method,
                            path: (req as any).originalUrl || req.url,
                            status: res.statusCode,
                            durMs: Date.now() - t0,
                            headers: {}
                        },
                        t: Date.now()
                    }]
                });
            });
            next();
        });
    };
}

export function reproMongoosePlugin(cfg: { appId: string; appSecret: string; apiBase: string }) {
    return function (schema: Schema) {
        // PRE: save
        schema.pre('save', { document: true }, async function (next) {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return next();
            try {
                const model = this.constructor as Model<any>;
                (this as any).__repro_meta = {
                    wasNew: this.isNew,
                    before: this.isNew ? null : await model.findById(this._id).lean().exec(),
                    collection: (this as any).collection.name,
                };
            } catch {}
            next();
        });

        // POST: save
        schema.post('save', { document: true }, function () {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return;
            const meta = (this as any).__repro_meta || {};
            const before = meta.before ?? null;
            const after = this.toObject({ depopulate: true });
            const collection = meta.collection || (this as any).collection.name;

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


        schema.pre<Query<any, any>>('findOneAndUpdate', async function (next) {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return next();
            try {
                const filter = this.getFilter();
                const model = this.model as Model<any>;
                (this as any).__repro_before = await model.findOne(filter).lean().exec();
                this.setOptions({ new: true });
            } catch {}
            next();
        });

        schema.post<Query<any, any>>('findOneAndUpdate', function (res: any) {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return;
            const before = (this as any).__repro_before ?? null;
            const after = res ?? null;
            const collection = this.model.collection.name;
            const pk = after?._id ?? before?._id;

            post(cfg.apiBase, cfg.appId, cfg.appSecret, (getCtx().sid as string), {
                entries: [{
                    actionId: aid!,
                    db: [{ collection, pk: { _id: pk }, before, after, op: after && before ? 'update' : after ? 'insert' : 'update' }],
                    t: Date.now()
                }]
            });
        });


        // deleteOne (correct options + getFilter + Query typing)
        schema.pre<Query<any, any>>('deleteOne', { document: false, query: true }, async function (next) {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return next();
            try {
                const filter = this.getFilter();
                const model = this.model as Model<any>;
                (this as any).__repro_before = await model.findOne(filter).lean().exec();
            } catch {}
            next();
        });

        schema.post<Query<any, any>>('deleteOne', { document: false, query: true }, function () {
            const { sid, aid } = getCtx();
            if (!sid || !aid) return;
            const before = (this as any).__repro_before ?? null;
            if (!before) return;

            const collection = this.model.collection.name;
            post(cfg.apiBase, cfg.appId, cfg.appSecret, sid!, {
                entries: [{
                    actionId: aid!,
                    db: [{ collection, pk: { _id: before._id }, before, after: null, op: 'delete' }],
                    t: Date.now()
                }]
            });
        });
    };
}
