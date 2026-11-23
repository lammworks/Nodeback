'use strict';

/**
 * Spec for committed deploy-log credential disclosure.
 *
 * These tests fail while credential material is still recoverable from git
 * history reachable from HEAD. They pass once those blobs are gone and
 * gitignore covers the debug logs and the functions env file.
 *
 * Run from the repository root:
 *   node --test functions/test/committed-deploy-credentials.test.js
 *
 * The auth check posts only to the local process. It does not contact the
 * deployed functions, the mailbox, or the payment provider.
 */

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { test } = require('node:test');

const repoRoot = path.resolve(__dirname, '..', '..');
const functionsDir = path.join(repoRoot, 'functions');

const RUNTIME_CONFIG_VARIABLES = new Set([
  'password',
  'frontend_token',
  'dashboard_token',
]);

const FUNCTION_SECRET_KEYS = new Set([
  'API_KEY',
  'API_SECRET',
  'ACCESS_KEY',
  'SIGNATURE',
  'PROFILE_ID',
  'EMAIL_PASS',
  'SQUARE_ACCESS_TOKEN',
  'SQUARE_APPLICATION_ID',
]);

const NAMED_FUNCTIONS = [
  'addressSearch',
  'coupon',
  'register',
  'newAddress',
  'cybersource',
];

const PLACEHOLDERS = new Set([
  '',
  'changeme',
  'change-me',
  'password',
  'secret',
  'token',
  'your-api-key',
  'your_api_key',
  'placeholder',
  'todo',
  'example',
  'xxx',
  'redacted',
  'null',
  'undefined',
  'none',
  'test',
  'testing',
]);

function git(args) {
  return execFileSync('git', ['-C', repoRoot, ...args], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
}

function isPlaceholder(value) {
  if (typeof value !== 'string') {
    return true;
  }
  const trimmed = value.trim();
  if (PLACEHOLDERS.has(trimmed.toLowerCase())) {
    return true;
  }
  return /^[*xX.]+$/.test(trimmed);
}

function isDebugLog(filePath) {
  return filePath === 'firebase-debug.log' || filePath.endsWith('/firebase-debug.log');
}

function isEnvFile(filePath) {
  return filePath === '.env' || filePath.endsWith('/.env');
}

function trackedBlobs() {
  const seen = new Map();
  const listing = git(['rev-list', '--objects', 'HEAD']);
  for (const line of listing.split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    if (space === -1) continue;
    const sha = line.slice(0, space);
    const filePath = line.slice(space + 1);
    if (!isDebugLog(filePath) && !isEnvFile(filePath)) continue;
    const key = `${sha} ${filePath}`;
    if (!seen.has(key)) seen.set(key, { sha, filePath });
  }
  return [...seen.values()];
}

function blobText(sha) {
  return git(['cat-file', '-p', sha]);
}

function parseJsonBody(line) {
  const start = line.indexOf('{');
  if (start === -1) return null;
  try {
    return JSON.parse(line.slice(start));
  } catch {
    return null;
  }
}

function walk(node, visit) {
  if (!node || typeof node !== 'object') return;
  visit(node);
  if (Array.isArray(node)) {
    for (const item of node) walk(item, visit);
    return;
  }
  for (const value of Object.values(node)) walk(value, visit);
}

function variableName(resourceName) {
  if (typeof resourceName !== 'string') return null;
  const marker = '/variables/';
  const at = resourceName.lastIndexOf(marker);
  if (at === -1) return null;
  return resourceName.slice(at + marker.length);
}

function entryPointOf(node) {
  if (typeof node.entryPoint === 'string' && node.entryPoint) {
    return node.entryPoint;
  }
  if (typeof node.name === 'string') {
    const parts = node.name.split('/');
    return parts[parts.length - 1] || node.name;
  }
  return '(unknown)';
}

function leaksInDebugLog(filePath, text) {
  const leaks = [];
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const body = parseJsonBody(lines[index]);
    if (!body) continue;
    const line = index + 1;
    walk(body, (node) => {
      const variable = variableName(node.name);
      if (
        variable &&
        RUNTIME_CONFIG_VARIABLES.has(variable) &&
        typeof node.text === 'string' &&
        !isPlaceholder(node.text)
      ) {
        leaks.push({
          filePath,
          line,
          kind: 'runtime-config',
          name: variable,
          length: node.text.length,
          value: node.text,
        });
      }
      if (node.environmentVariables && typeof node.environmentVariables === 'object') {
        const entryPoint = entryPointOf(node);
        for (const key of FUNCTION_SECRET_KEYS) {
          const value = node.environmentVariables[key];
          if (typeof value === 'string' && !isPlaceholder(value)) {
            leaks.push({
              filePath,
              line,
              kind: 'environment',
              name: `${entryPoint}.${key}`,
              entryPoint,
              key,
              length: value.length,
              value,
            });
          }
        }
      }
    });
  }
  return leaks;
}

function leaksInEnv(filePath, text) {
  const leaks = [];
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue;
    const eq = trimmed.indexOf('=');
    const key = trimmed.slice(0, eq).replace(/^export\s+/, '').trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!FUNCTION_SECRET_KEYS.has(key) || isPlaceholder(value)) continue;
    leaks.push({
      filePath,
      line: index + 1,
      kind: 'env-file',
      name: key,
      key,
      length: value.length,
      value,
    });
  }
  return leaks;
}

function recoverableLeaks() {
  const leaks = [];
  for (const blob of trackedBlobs()) {
    const text = blobText(blob.sha);
    if (isDebugLog(blob.filePath)) {
      leaks.push(...leaksInDebugLog(blob.filePath, text));
    } else {
      leaks.push(...leaksInEnv(blob.filePath, text));
    }
  }
  return leaks;
}

function describeLeak(leak) {
  return `${leak.filePath}:${leak.line} ${leak.kind} ${leak.name} length=${leak.length}`;
}

function ignoreRules() {
  const files = [
    { base: '', file: path.join(repoRoot, '.gitignore') },
    { base: 'functions', file: path.join(repoRoot, 'functions', '.gitignore') },
  ];
  const rules = [];
  for (const entry of files) {
    if (!fs.existsSync(entry.file)) continue;
    for (const raw of fs.readFileSync(entry.file, 'utf8').split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#') || line.startsWith('!')) continue;
      rules.push({ base: entry.base, pattern: line.replace(/^\//, '') });
    }
  }
  return rules;
}

function ruleMatches(rule, filePath) {
  let relative = filePath;
  if (rule.base) {
    const prefix = `${rule.base}/`;
    if (!filePath.startsWith(prefix)) return false;
    relative = filePath.slice(prefix.length);
  }
  const baseName = path.posix.basename(relative);
  const pattern = rule.pattern;
  if (pattern === relative || pattern === baseName) return true;
  if (pattern === `**/${baseName}`) return true;
  if (pattern === '*.log' && baseName.endsWith('.log')) return true;
  if (pattern === 'firebase-debug*.log' && /^firebase-debug.*\.log$/.test(baseName)) return true;
  if ((pattern === '.env' || pattern === '.env*') && (baseName === '.env' || baseName.startsWith('.env.'))) {
    return pattern === '.env' ? baseName === '.env' : true;
  }
  if (pattern === '**/.env' && baseName === '.env') return true;
  return false;
}

function isIgnored(filePath) {
  return ignoreRules().some((rule) => ruleMatches(rule, filePath));
}

function postPayment(handler, apiKey, apiSecret) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/payment_form',
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'content-length': Buffer.byteLength('{}'),
            'x-api-key': apiKey,
            'x-api-secret': apiSecret,
          },
        },
        (res) => {
          res.resume();
          res.on('end', () => {
            server.close(() => resolve(res.statusCode));
          });
        },
      );
      req.on('error', (error) => {
        server.close(() => reject(error));
      });
      req.end('{}');
    });
  });
}

function silenceConsole() {
  const methods = ['log', 'info', 'warn', 'error', 'debug'];
  const previous = {};
  for (const method of methods) {
    previous[method] = console[method];
    console[method] = () => {};
  }
  return () => {
    for (const method of methods) console[method] = previous[method];
  };
}

test('committed deploy logs and env files do not disclose function credentials', async () => {
  const leaks = recoverableLeaks();
  const described = [...new Set(leaks.map(describeLeak))].sort();
  const failures = [];

  const pairs = new Map();
  for (const leak of leaks) {
    if (leak.kind !== 'environment' || leak.entryPoint !== 'cybersource') continue;
    if (leak.key !== 'API_KEY' && leak.key !== 'API_SECRET') continue;
    const id = `${leak.filePath}:${leak.line}`;
    if (!pairs.has(id)) pairs.set(id, { where: id });
    pairs.get(id)[leak.key] = leak.value;
  }
  const usable = [];
  const seenPairs = new Set();
  for (const pair of pairs.values()) {
    if (!pair.API_KEY || !pair.API_SECRET) continue;
    const digest = crypto.createHash('sha256').update(pair.API_KEY).update('\0').update(pair.API_SECRET).digest('hex');
    if (seenPairs.has(digest)) continue;
    seenPairs.add(digest);
    usable.push(pair);
  }

  if (usable.length > 0) {
    const restoreConsole = silenceConsole();
    const previousCwd = process.cwd();
    try {
      process.chdir(functionsDir);
      const { cybersource } = require('../index.js');
      for (const pair of usable) {
        const status = await postPayment(cybersource, pair.API_KEY, pair.API_SECRET);
        if (status !== 401) {
          failures.push(
            `cybersource accepted API credentials recovered from ${pair.where} (status ${status})`,
          );
        }
      }
    } finally {
      process.chdir(previousCwd);
      restoreConsole();
    }
  }

  const runtime = described.filter((line) => line.includes(' runtime-config '));
  if (runtime.length > 0) {
    failures.push(
      'runtime-config responses in committed debug logs still contain credential text:\n'
      + runtime.join('\n'),
    );
  }

  for (const entryPoint of NAMED_FUNCTIONS) {
    const forFunction = described.filter((line) => line.includes(` ${entryPoint}.`));
    if (forFunction.length > 0) {
      failures.push(
        `${entryPoint} credential environment variables are still recoverable from committed debug logs:\n`
        + forFunction.join('\n'),
      );
    }
  }

  const envFile = described.filter((line) => line.includes(' env-file '));
  if (envFile.length > 0) {
    failures.push('tracked .env files still assign credential values:\n' + envFile.join('\n'));
  }

  for (const filePath of [
    'firebase-debug.log',
    'functions/firebase-debug.log',
    'functions/.env',
  ]) {
    if (!isIgnored(filePath)) {
      failures.push(`${filePath} is not covered by a gitignore rule`);
    }
  }

  assert.deepEqual(failures, []);
});
