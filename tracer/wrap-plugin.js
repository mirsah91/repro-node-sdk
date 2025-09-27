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

        function escapeRx(s){ return s.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&'); }

        const obj = kv => t.objectExpression(
            Object.entries(kv).filter(([,v])=>v!=null)
                .map(([k,v]) => t.objectProperty(t.identifier(k),
                    typeof v === 'string' ? t.stringLiteral(v) : t.numericLiteral(v)))
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
                t.callExpression(t.memberExpression(t.identifier('__trace'), t.identifier('enter')),
                    [ t.stringLiteral(name), obj({ file, line }) ])
            );
            const exit = t.expressionStatement(
                t.callExpression(t.memberExpression(t.identifier('__trace'), t.identifier('exit')),
                    [ obj({ fn: name, file, line }) ])
            );

            const wrapped = t.blockStatement([ enter, t.tryStatement(body, null, t.blockStatement([ exit ])) ]);
            if (path.isFunction() || path.isClassMethod() || path.isObjectMethod()) {
                path.get('body').replaceWith(wrapped);
            }
            n.__wrapped = true;
        }

        return {
            name: 'omnitrace-wrap-functions',
            visitor: {
                FunctionDeclaration: wrap,
                FunctionExpression: wrap,
                ArrowFunctionExpression: wrap,
                ObjectMethod: wrap,
                ClassMethod: wrap,
                ClassPrivateMethod: wrap,
            }
        };
    };
};
