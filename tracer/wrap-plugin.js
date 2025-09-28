// wrap-plugin.js
module.exports = function makeWrapPlugin(filenameForMeta, opts = {}) {
    return ({ types: t }) => {
        const {
            mode = 'all',                 // 'all' | 'allowlist'
            allowFns = [],                // regexes or strings
            wrapGettersSetters = false,   // skip noisy accessors by default
            skipAnonymous = false,        // don't wrap anon fns in node_modules
        } = opts;

        const allowFnRegexes = allowFns.map(p =>
            typeof p === 'string' ? new RegExp(`^${escapeRx(p)}$`) : p
        );

        function escapeRx(s){ return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

        const obj = kv => t.objectExpression(
            Object.entries(kv).filter(([,v])=>v!=null)
                .map(([k,v]) => t.objectProperty(
                    t.identifier(k),
                    typeof v === 'string' ? t.stringLiteral(v) : t.numericLiteral(v)
                ))
        );

        function nameFor(path){
            const n = path.node;
            if (n.id?.name) return n.id.name;
            if ((path.isClassMethod() || path.isObjectMethod()) && n.key) {
                if (t.isIdentifier(n.key)) return n.key.name;
                if (t.isStringLiteral(n.key)) return n.key.value;
                if (t.isNumericLiteral(n.key)) return String(n.key.value);
            }
            if (path.parentPath?.isVariableDeclarator() && t.isIdentifier(path.parentPath.node.id))
                return path.parentPath.node.id.name;
            if (path.parentPath?.isAssignmentExpression()) {
                const left = path.parentPath.node.left;
                if (t.isIdentifier(left)) return left.name;
                if (t.isMemberExpression(left)) {
                    const p = left.property;
                    if (t.isIdentifier(p)) return p.name;
                    if (t.isStringLiteral(p)) return p.value;
                    if (t.isNumericLiteral(p)) return String(p.value);
                }
            }
            return '(anonymous)';
        }

        function shouldWrap(path, name){
            // skip getters/setters unless asked
            if (!wrapGettersSetters &&
                (path.node.kind === 'get' || path.node.kind === 'set')) return false;

            if (skipAnonymous && name === '(anonymous)') return false;

            if (mode === 'allowlist') {
                return allowFnRegexes.length === 0
                    ? false
                    : allowFnRegexes.some(rx => rx.test(name));
            }
            return true; // mode 'all'
        }

        function wrap(path){
            const n = path.node;
            if (n.__wrapped) return;

            const name = nameFor(path);
            if (!shouldWrap(path, name)) return;

            const line = n.loc?.start?.line ?? null;
            const file = filenameForMeta;

            let body = n.body;
            if (t.isArrowFunctionExpression(n) && !t.isBlockStatement(body)) {
                body = t.blockStatement([ t.returnStatement(body) ]);
            }
            if (!t.isBlockStatement(body)) return;

            const enter = t.expressionStatement(
                t.callExpression(
                    t.memberExpression(t.identifier('__trace'), t.identifier('enter')),
                    [ t.stringLiteral(name), obj({ file, line }) ]
                )
            );
            const exit = t.expressionStatement(
                t.callExpression(
                    t.memberExpression(t.identifier('__trace'), t.identifier('exit')),
                    [ obj({ fn: name, file, line }) ]
                )
            );

            const wrapped = t.blockStatement([ enter, t.tryStatement(body, null, t.blockStatement([ exit ])) ]);
            if (path.isFunction() || path.isClassMethod() || path.isObjectMethod()) {
                path.get('body').replaceWith(wrapped);
            }
            n.__wrapped = true;
        }

        // ---- NEW: wrap every call-site with __repro_call(...) ----
        function wrapCall(path, state) {
            const n = path.node;
            if (n.__repro_call_wrapped) return;

            // Don’t wrap our own helper, super() or dynamic import()
            if (t.isIdentifier(n.callee, { name: '__repro_call' })) return;
            if (t.isSuper(n.callee)) return;
            if (t.isImport(n.callee)) return;

            // Optional chaining calls are tricky to preserve exactly; skip for now
            // (If needed, we can add a nullish check + temp variables.)
            if (n.optional === true) return;

            // Determine thisArg and a friendly label (best-effort)
            let thisArg = t.nullLiteral();
            let label = null;

            if (t.isMemberExpression(n.callee)) {
                thisArg = n.callee.object;
                if (t.isIdentifier(n.callee.property)) {
                    label = t.stringLiteral(n.callee.property.name);
                } else if (t.isStringLiteral(n.callee.property)) {
                    label = t.stringLiteral(n.callee.property.value);
                }
            } else if (t.isIdentifier(n.callee)) {
                label = t.stringLiteral(n.callee.name);
            }

            const argsArray = t.arrayExpression(n.arguments); // preserves spreads
            const fileLit = t.stringLiteral(state.file.opts.filename || '');
            const lineLit = t.numericLiteral(n.loc?.start?.line ?? 0);
            const labelLit = label || t.stringLiteral('');

            const callShim = t.callExpression(
                t.identifier('__repro_call'),
                [ n.callee, thisArg, argsArray, fileLit, lineLit, labelLit ]
            );

            path.replaceWith(callShim);
            path.node.__repro_call_wrapped = true;
        }

        return {
            name: 'omnitrace-wrap-functions-and-calls',
            visitor: {
                // function body enter/exit
                FunctionDeclaration: wrap,
                FunctionExpression: wrap,
                ArrowFunctionExpression: wrap,
                ObjectMethod: wrap,
                ClassMethod: wrap,
                ClassPrivateMethod: wrap,

                // call-site wrapping
                CallExpression: {
                    exit(path, state) { wrapCall(path, state); }
                },
                // (If you also want to wrap OptionalCallExpression in older Babel ASTs,
                // add the same handler here)
            }
        };
    };
};
