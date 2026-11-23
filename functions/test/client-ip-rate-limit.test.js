'use strict';

/**
 * Spec for the checkout rate limiter in functions/app.js.
 *
 * The daily cap must follow the socket address Node records for the
 * connection (the address Express exposes as req.ip while trust proxy is
 * off, or the platform client address once trust proxy is limited to the
 * load-balancer hop). A caller-supplied x-fastly-client-ip value must not
 * select a different quota, and a second socket must not inherit a quota
 * already consumed under that header.
 *
 * These tests fail while the limiter stores its quota under
 * req.headers['x-fastly-client-ip'].
 *
 * The HTTPS transport is replaced only at https.request, which is the call
 * axios 1.4.0 / follow-redirects make for the payment gateway. The stub
 * records that call and returns a local response so the suite does not open
 * a connection to the payment host. Nothing is substituted for Express,
 * the rate-limit middleware, or the route handlers.
 */

const assert = require('node:assert/strict');
const http = require('http');
const https = require('https');
const { describe, test, before } = require('node:test');
const { EventEmitter } = require('events');
const { Readable } = require('stream');

const DAILY_CAP = 100;
const GATEWAY_HOST = 'testsecureacceptance.cybersource.com';
const GATEWAY_PATH = '/pay';

const gatewayCalls = [];

function installGatewayCapture() {
  https.request = function captureGatewayRequest(options, callback) {
    const chunks = [];
    const fake = new EventEmitter();
    fake.finished = false;
    fake.aborted = false;
    fake.setHeader = () => fake;
    fake.removeHeader = () => fake;
    fake.getHeader = (name) => options.headers && options.headers[name];
    fake.abort = () => {
      fake.aborted = true;
      fake.emit('abort');
      return fake;
    };
    fake.destroy = (err) => {
      if (err) fake.emit('error', err);
      return fake;
    };
    fake.setTimeout = () => fake;
    fake.setNoDelay = () => fake;
    fake.setSocketKeepAlive = () => fake;
    fake.write = (data, encoding, cb) => {
      if (typeof encoding === 'function') {
        cb = encoding;
        encoding = undefined;
      }
      if (data && data.length) {
        chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(data, encoding || 'utf8'));
      }
      if (cb) cb();
      return true;
    };
    fake.end = (data, encoding, cb) => {
      if (typeof data === 'function') {
        cb = data;
        data = undefined;
        encoding = undefined;
      } else if (typeof encoding === 'function') {
        cb = encoding;
        encoding = undefined;
      }
      if (data) fake.write(data, encoding);
      fake.finished = true;
      gatewayCalls.push({
        protocol: options.protocol,
        hostname: options.hostname || options.host,
        path: options.path,
        method: options.method,
        headers: options.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      });
      const payload = Buffer.from('stub-gateway-ok');
      const res = Readable.from([payload]);
      res.statusCode = 200;
      res.statusMessage = 'OK';
      res.headers = {
        'content-type': 'text/plain',
        'content-length': String(payload.length),
      };
      if (callback) callback(res);
      if (cb) cb();
      return fake;
    };
    return fake;
  };
}

function loadCybersource() {
  const indexPath = require.resolve('../index');
  const appPath = require.resolve('../app');
  delete require.cache[indexPath];
  delete require.cache[appPath];
  return require('../index').cybersource;
}

function listen(handler, host) {
  const server = http.createServer(handler);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    const onListening = () => {
      resolve({
        port: server.address().port,
        close: () => new Promise((done, fail) => {
          server.close((err) => (err ? fail(err) : done()));
        }),
      });
    };
    if (host === '::') {
      server.listen({ port: 0, host: '::', ipv6Only: false }, onListening);
    } else {
      server.listen(0, host || '127.0.0.1', onListening);
    }
  });
}

function post({ host, port, path, headers, json }) {
  const payload = Buffer.from(JSON.stringify(json));
  return new Promise((resolve, reject) => {
    const req = http.request({
      host,
      port,
      family: host.includes(':') ? 6 : 4,
      method: 'POST',
      path,
      headers: {
        'content-type': 'application/json',
        'content-length': String(payload.length),
        ...headers,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          body: Buffer.concat(chunks).toString('utf8'),
          headers: res.headers,
        });
      });
    });
    req.on('error', reject);
    req.end(payload);
  });
}

async function postMany(options, count) {
  const results = [];
  for (let i = 0; i < count; i += 1) {
    results.push(await post(options));
  }
  return results;
}

describe('checkout rate limit is keyed by the socket address', { concurrency: 1 }, () => {
  before(() => {
    installGatewayCapture();
    // The handlers log every body. Keep the assertion report readable.
    console.log = () => {};
  });

  test('payment_submit keeps one quota when x-fastly-client-ip changes', async () => {
    const handler = loadCybersource();
    const server = await listen(handler);
    const before = gatewayCalls.length;
    try {
      const allowed = await postMany({
        host: '127.0.0.1',
        port: server.port,
        path: '/payment_submit',
        headers: { 'X-Fastly-Client-Ip': '203.0.113.10' },
        json: { amount: '10.00', reference_number: 'socket-a' },
      }, DAILY_CAP);

      for (const res of allowed) {
        assert.equal(res.status, 200, res.body);
        assert.equal(res.body, 'stub-gateway-ok');
      }
      assert.equal(gatewayCalls.length, before + DAILY_CAP);
      const posted = gatewayCalls[gatewayCalls.length - 1];
      assert.equal(posted.protocol, 'https:');
      assert.equal(posted.hostname, GATEWAY_HOST);
      assert.equal(posted.path, GATEWAY_PATH);
      assert.equal(posted.method, 'POST');
      assert.equal(posted.headers['Content-Type'], 'application/x-www-form-urlencoded');
      assert.equal(posted.body, 'amount=10.00&reference_number=socket-a');

      const rotated = await post({
        host: '127.0.0.1',
        port: server.port,
        path: '/payment_submit',
        headers: {
          'X-Fastly-Client-Ip': '203.0.113.99',
          'X-Forwarded-For': '198.51.100.20',
        },
        json: { amount: '10.00', reference_number: 'rotated' },
      });

      assert.equal(
        rotated.status,
        429,
        `rotated client header was given a new quota: ${rotated.status} ${rotated.body}`
      );
      assert.equal(
        gatewayCalls.length,
        before + DAILY_CAP,
        'payment gateway was contacted after the daily cap'
      );
      assert.equal(gatewayCalls.some((call) => call.body.includes('reference_number=rotated')), false);
    } finally {
      await server.close();
    }
  });

  test('payment_submit gives a second socket its own quota for the same header', async () => {
    const handler = loadCybersource();
    const server = await listen(handler, '::');
    const before = gatewayCalls.length;
    const headers = { 'X-Fastly-Client-Ip': '203.0.113.50' };
    try {
      const firstSocket = await postMany({
        host: '127.0.0.1',
        port: server.port,
        path: '/payment_submit',
        headers,
        json: { amount: '10.00', reference_number: 'first-socket' },
      }, DAILY_CAP);
      for (const res of firstSocket) {
        assert.equal(res.status, 200, res.body);
      }

      const secondSocket = await post({
        host: '::1',
        port: server.port,
        path: '/payment_submit',
        headers,
        json: { amount: '10.00', reference_number: 'second-socket' },
      });

      assert.notEqual(
        secondSocket.status,
        429,
        'a different socket address was charged against the first socket quota'
      );
      assert.equal(secondSocket.status, 200, secondSocket.body);
      assert.equal(gatewayCalls.length, before + DAILY_CAP + 1);
      assert.equal(
        gatewayCalls[gatewayCalls.length - 1].body,
        'amount=10.00&reference_number=second-socket'
      );

      const stillFirstSocket = await post({
        host: '127.0.0.1',
        port: server.port,
        path: '/payment_submit',
        headers: { 'X-Fastly-Client-Ip': '203.0.113.77' },
        json: { amount: '10.00', reference_number: 'first-socket-rotated' },
      });
      assert.equal(stillFirstSocket.status, 429, stillFirstSocket.body);
      assert.equal(gatewayCalls.length, before + DAILY_CAP + 1);
    } finally {
      await server.close();
    }
  });

  test('payment_form keeps one quota when x-fastly-client-ip changes', async () => {
    const handler = loadCybersource();
    const server = await listen(handler);
    const before = gatewayCalls.length;
    try {
      const allowed = await postMany({
        host: '127.0.0.1',
        port: server.port,
        path: '/payment_form',
        headers: { 'X-Fastly-Client-Ip': '203.0.113.20' },
        json: { amount: '10.00', reference_number: 'form' },
      }, DAILY_CAP);

      for (const res of allowed) {
        assert.equal(res.status, 401, res.body);
      }
      assert.equal(gatewayCalls.length, before);

      const rotated = await post({
        host: '127.0.0.1',
        port: server.port,
        path: '/payment_form',
        headers: { 'X-Fastly-Client-Ip': '203.0.113.21' },
        json: { amount: '10.00', reference_number: 'form-rotated' },
      });

      assert.equal(
        rotated.status,
        429,
        `rotated client header reached payment_form auth: ${rotated.status} ${rotated.body}`
      );
      assert.equal(gatewayCalls.length, before);
    } finally {
      await server.close();
    }
  });

  test('a stable x-fastly-client-ip value is still capped at 100 payment_submit calls', async () => {
    const handler = loadCybersource();
    const server = await listen(handler);
    const before = gatewayCalls.length;
    try {
      const allowed = await postMany({
        host: '127.0.0.1',
        port: server.port,
        path: '/payment_submit',
        headers: { 'X-Fastly-Client-Ip': '203.0.113.40' },
        json: { amount: '10.00', reference_number: 'stable' },
      }, DAILY_CAP);
      for (const res of allowed) {
        assert.equal(res.status, 200, res.body);
      }

      const extra = await post({
        host: '127.0.0.1',
        port: server.port,
        path: '/payment_submit',
        headers: { 'X-Fastly-Client-Ip': '203.0.113.40' },
        json: { amount: '10.00', reference_number: 'stable-over' },
      });
      assert.equal(extra.status, 429, extra.body);
      assert.equal(gatewayCalls.length, before + DAILY_CAP);
    } finally {
      await server.close();
    }
  });
});
