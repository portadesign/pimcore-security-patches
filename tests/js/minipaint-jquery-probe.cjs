'use strict';

const fs = require('node:fs');
const vm = require('node:vm');

const MODULE_PREFIX = '!function(e){var t={};';
const MODULE_PREFIX_CAPTURING = '!function(e){globalThis.__modules=e;var t={};';
const JQUERY_MARKER = 'expando:"jQuery"';

const CHECK_PAYLOADS = [
    '<style><style /><img src=x onerror=alert(1)>',
    '<style><style/><img src=x onerror=_=1>',
    '<div><style><style /><img src=x onerror=alert(1)></style></div>',
    '<span/>',
];

function stub() {
    return new Proxy(function () {}, {
        get: (target, key) => {
            if (key === Symbol.toPrimitive) {
                return () => '';
            }
            if (key === 'length') {
                return 0;
            }
            if (key === 'nodeType') {
                return 9;
            }

            return stub();
        },
        apply: () => stub(),
        construct: () => stub(),
        set: () => true,
        has: () => true,
    });
}

function loadJquery(bundlePath) {
    const source = fs.readFileSync(bundlePath, 'utf8');
    if (!source.includes(MODULE_PREFIX)) {
        throw new Error('unexpected bundle layout');
    }

    const sandbox = {
        location: { href: 'http://localhost/', protocol: 'http:' },
        navigator: { userAgent: 'node', hardwareConcurrency: 2 },
        addEventListener() {},
        removeEventListener() {},
        setTimeout,
        clearTimeout,
        document: stub(),
    };
    sandbox.window = sandbox;
    sandbox.self = sandbox;
    sandbox.globalThis = sandbox;

    try {
        vm.runInNewContext(source.replace(MODULE_PREFIX, MODULE_PREFIX_CAPTURING), sandbox, { timeout: 5000 });
    } catch (error) {
        if (!sandbox.__modules) {
            throw error;
        }
    }

    const modules = sandbox.__modules;
    const id = Object.keys(modules).find((key) => modules[key].toString().includes(JQUERY_MARKER));
    if (id === undefined) {
        throw new Error('jQuery module not found');
    }

    const module = { exports: {} };
    modules[id].call(module.exports, module, module.exports, () => {
        throw new Error('unexpected require');
    });

    return module.exports;
}

const [bundlePath, mode] = process.argv.slice(2);
if (!bundlePath) {
    process.stderr.write('usage: minipaint-jquery-probe.cjs <bundle.js> [--check|<json array of html strings>]\n');
    process.exit(2);
}

const jquery = loadJquery(bundlePath);
const inputs = mode === undefined || mode === '--check' ? CHECK_PAYLOADS : JSON.parse(mode);
const outputs = inputs.map((html) => jquery.htmlPrefilter(html));

if (mode === '--check') {
    const rewritten = inputs.filter((html, index) => outputs[index] !== html);
    rewritten.forEach((html) => process.stderr.write('rewritten: ' + html + '\n'));
    process.exit(rewritten.length === 0 ? 0 : 1);
}

process.stdout.write(JSON.stringify({ jquery: jquery.fn.jquery, outputs }) + '\n');
