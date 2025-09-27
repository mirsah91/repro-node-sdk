// cjs-hook.js
const fs = require('node:fs');
const Module = require('node:module');
const babel = require('@babel/core');
const tsPlugin = require('@babel/plugin-transform-typescript').default || require('@babel/plugin-transform-typescript');
const makeWrap = require('./wrap-plugin');

function installCJS({ include, exclude, parserPlugins }) {
    const ORIG = {
        js: Module._extensions['.js'],
        jsx: Module._extensions['.jsx'],
        ts: Module._extensions['.ts'],
        tsx: Module._extensions['.tsx'],
    };

    const should = f => {
        const s = f.replace(/\\/g,'/');
        if (exclude?.some(rx => rx.test(s))) return false;
        return !include || include.some(rx => rx.test(s));
    };

    const isExpressResponse = f => /node_modules[\\/]express[\\/]lib[\\/]response\.js$/.test(f.replace(/\\/g,'/'));
    const isMongooseQuery   = f => /node_modules[\\/]mongoose[\\/]lib[\\/]query\.js$/.test(f.replace(/\\/g,'/'));
    const isMongooseModel   = f => /node_modules[\\/]mongoose[\\/]lib[\\/]model\.js$/.test(f.replace(/\\/g,'/'));
    const isMongooseAgg     = f => /node_modules[\\/]mongoose[\\/]lib[\\/]aggregate\.js$/.test(f.replace(/\\/g,'/'));

    function pluginOptsFor(filename) {
        const s = filename.replace(/\\/g,'/');
        // Your app files: wrap everything (but skip getters/setters to cut chatter)
        if (!/node_modules[\\/]/.test(s)) {
            return { mode: 'all', wrapGettersSetters: false, skipAnonymous: false };
        }
        // Express: only response API we care about
        if (isExpressResponse(s)) {
            return { mode: 'allowlist', allowFns: [/^(json|send|end|status|set|header|get)$/], skipAnonymous: true };
        }
        // Mongoose core: focus on public query/model ops
        if (isMongooseQuery(s) || isMongooseModel(s) || isMongooseAgg(s)) {
            return {
                mode: 'allowlist',
                allowFns: [
                    /^(find|findOne|findById|findOneAnd\w+|update\w*|replaceOne|save|delete\w*|remove|count\w*|aggregate|create|insertMany|distinct|lean|exec)$/i
                ],
                skipAnonymous: true
            };
        }
        // default for other node_modules files we matched via include: wrap nothing
        return { mode: 'allowlist', allowFns: [], skipAnonymous: true };
    }

    function handler(orig){
        return function (module, filename){
            if (!should(filename)) return orig(module, filename);

            const code = fs.readFileSync(filename, 'utf8');
            const pluginOpts = pluginOptsFor(filename);
            const out = babel.transformSync(code, {
                filename,
                sourceType: 'unambiguous',
                retainLines: true,
                parserOpts: { sourceType:'unambiguous', plugins: parserPlugins },
                plugins: [[ makeWrap(filename, pluginOpts) ], [ tsPlugin, { allowDeclareFields: true } ]]
            })?.code || code;

            module._compile(out, filename);
        };
    }

    Module._extensions['.js']  = handler(ORIG.js);
    Module._extensions['.jsx'] = handler(ORIG.jsx || ORIG.js);
    Module._extensions['.ts']  = handler(ORIG.ts  || ORIG.js);
    Module._extensions['.tsx'] = handler(ORIG.tsx || ORIG.jsx || ORIG.js);
}

module.exports = { installCJS };
