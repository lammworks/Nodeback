'use strict';

/**
 * Spec for the payment submit route.
 *
 * These tests fail while an unauthenticated caller can make this process post
 * their body to the payment host and read that host's response. They pass once
 * that relay is limited to a payment this service signed, and only after the
 * same API key check used by the payment form route.
 *
 * The stand-in replaces only the TCP socket. Express, the JSON parser, qs,
 * axios, and the Cloud Function wrapper all run.
 */

const assert = require('node:assert/strict');
const crypto = require('crypto');
const http = require('node:http');
const https = require('node:https');
const { after, before, describe, test } = require('node:test');
const qs = require('qs');

const GATEWAY_SENTINEL = 'GATEWAY_SENTINEL_payment_relay';
const PAY_HOST = 'testsecureacceptance.cybersource.com';
const PAY_PATH = '/pay';

const outbound = [];

https.request = function patchedHttpsRequest(options, callback) {
  if (typeof options === 'string') {
    options = new URL(options);
  }
  const chunks = [];
  const request = new (require('node:events').EventEmitter)();
  request.destroyed = false;
  request.aborted = false;
  request.finished = false;
  request.setHeader = function setHeader() {
    return request;
  };
  request.getHeader = function getHeader() {
    return undefined;
  };
  request.removeHeader = function removeHeader() {
    return request;
  };
  request.setTimeout = function setTimeout() {
    return request;
  };
  request.destroy = function destroy() {
    request.destroyed = true;
    return request;
  };
  request.abort = function abort() {
    request.aborted = true;
    request.emit('abort');
  };
  request.write = function write(data, encoding, cb) {
    if (typeof encoding === 'function') {
      cb = encoding;
      encoding = undefined;
    }
    if (data && data.length) {
      chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(data, encoding || 'utf8'));
    }
    if (typeof cb === 'function') {
      cb();
    }
    return true;
  };
  request.end = function end(data, encoding, cb) {
    if (typeof data === 'function') {
      cb = data;
      data = undefined;
      encoding = undefined;
    } else if (typeof encoding === 'function') {
      cb = encoding;
      encoding = undefined;
    }
    if (data) {
      request.write(data, encoding);
    }
    request.finished = true;
    const body = Buffer.concat(chunks).toString('utf8');
    outbound.push({
      protocol: options.protocol,
      hostname: options.hostname || options.host,
      path: options.path || options.pathname,
      method: options.method,
      body,
    });
    const response = new (require('node:stream').Readable)({
      read() {},
    });
    response.statusCode = 200;
    response.statusMessage = 'OK';
    response.headers = { 'content-type': 'text/html; charset=utf-8' };
    response.req = request;
    process.nextTick(() => {
      callback(response);
      response.push(GATEWAY_SENTINEL);
      response.push(null);
    });
    if (typeof cb === 'function') {
      cb();
    }
    return request;
  };
  return request;
};

// Placeholders only. Set before the app loads so dotenv does not replace them.
process.env.API_KEY = 'placeholder-api-key';
process.env.API_SECRET = 'placeholder-api-secret';
process.env.SIGNATURE = 'placeholder-signature';
process.env.ACCESS_KEY = 'placeholder-access-key';
process.env.PROFILE_ID = 'placeholder-profile-id';

const { cybersource } = require('../index');

function signPayment(paymentDetails) {
  const fieldOrder = paymentDetails.signed_field_names.split(',');
  const data = fieldOrder.map((field) => `${field}=${paymentDetails[field]}`).join(',');
  return crypto.createHmac('sha256', process.env.SIGNATURE).update(data).digest('base64');
}

function signedPayment(overrides) {
  const payment = {
    access_key: 'placeholder-access-key',
    profile_id: 'placeholder-profile-id',
    transaction_uuid: 'placeholder-uuid',
    signed_field_names:
      'access_key,profile_id,transaction_uuid,signed_field_names,unsigned_field_names,amount,currency,reference_number',
    unsigned_field_names: '',
    amount: '10.00',
    currency: 'USD',
    reference_number: 'ref-placeholder',
    ...overrides,
  };
  payment.signature = signPayment(payment);
  return payment;
}

describe('payment submit authentication', () => {
  let server;
  let baseUrl;

  before(async () => {
    server = http.createServer(cybersource);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    if (server) {
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });

  async function post(path, { headers, body, raw, contentType } = {}) {
    outbound.length = 0;
    const response = await fetch(baseUrl + path, {
      method: 'POST',
      headers: {
        'content-type': contentType === undefined ? 'application/json' : contentType,
        ...headers,
      },
      body: raw !== undefined ? raw : JSON.stringify(body === undefined ? {} : body),
    });
    const text = await response.text();
    return { status: response.status, text, outbound: outbound.slice() };
  }

  function apiHeaders(extra) {
    return {
      'x-api-key': process.env.API_KEY,
      'x-api-secret': process.env.API_SECRET,
      ...extra,
    };
  }

  function assertNoRelay(result) {
    assert.equal(
      result.outbound.length,
      0,
      `payment host was contacted before the route refused the caller: ${JSON.stringify(result.outbound)}`
    );
    assert.equal(result.text.includes(GATEWAY_SENTINEL), false);
  }

  test('payment form route rejects a caller with no API key', async () => {
    const result = await post('/payment_form', {
      body: { amount: '10.00', reference_number: 'ref-placeholder' },
    });
    assert.equal(result.status, 401);
    assert.deepEqual(JSON.parse(result.text), { error: 'Invalid API key' });
    assertNoRelay(result);
  });

  test('unauthenticated JSON submit does not relay or return the gateway body', async () => {
    const result = await post('/payment_submit', {
      body: {
        amount: '10.00',
        currency: 'USD',
        reference_number: 'attacker-ref',
        card_number: 'test-card-placeholder',
      },
    });
    assertNoRelay(result);
    assert.equal(result.status, 401);
    assert.deepEqual(JSON.parse(result.text), { error: 'Invalid API key' });
  });

  test('a signed payment is still refused when the API key is absent', async () => {
    const result = await post('/payment_submit', { body: signedPayment() });
    assertNoRelay(result);
    assert.equal(result.status, 401);
    assert.deepEqual(JSON.parse(result.text), { error: 'Invalid API key' });
  });

  test('a wrong API key is refused before any relay', async () => {
    const result = await post('/payment_submit', {
      headers: { 'x-api-key': 'wrong-placeholder', 'x-api-secret': process.env.API_SECRET },
      body: signedPayment(),
    });
    assertNoRelay(result);
    assert.equal(result.status, 401);
    assert.deepEqual(JSON.parse(result.text), { error: 'Invalid API key' });
  });

  test('a wrong API secret is refused before any relay', async () => {
    const result = await post('/payment_submit', {
      headers: { 'x-api-key': process.env.API_KEY, 'x-api-secret': 'wrong-placeholder' },
      body: signedPayment(),
    });
    assertNoRelay(result);
    assert.equal(result.status, 401);
    assert.deepEqual(JSON.parse(result.text), { error: 'Invalid API secret' });
  });

  test('slash, case, and query variants of the submit path are refused without a key', async () => {
    for (const path of ['/payment_submit/', '/Payment_Submit', '/payment_submit?unused=1']) {
      const result = await post(path, {
        body: { amount: '25.00', reference_number: 'attacker-ref' },
      });
      assertNoRelay(result);
      assert.equal(result.status, 401, path);
      assert.deepEqual(JSON.parse(result.text), { error: 'Invalid API key' });
    }
  });

  test('a non-JSON submit body is refused before an empty form is relayed', async () => {
    const result = await post('/payment_submit', {
      contentType: 'text/plain',
      raw: 'amount=10.00',
    });
    assertNoRelay(result);
    assert.equal(result.status, 401);
    assert.deepEqual(JSON.parse(result.text), { error: 'Invalid API key' });
  });

  test('valid credentials do not relay a payment this service did not sign', async () => {
    const result = await post('/payment_submit', {
      headers: apiHeaders(),
      body: {
        amount: '10.00',
        currency: 'USD',
        reference_number: 'attacker-ref',
        card_number: 'test-card-placeholder',
      },
    });
    assertNoRelay(result);
    assert.equal(result.status, 400);
    assert.deepEqual(JSON.parse(result.text), { error: 'Invalid payment' });
  });

  test('valid credentials do not relay a payment whose signature is for a different amount', async () => {
    const payment = signedPayment({ amount: '10.00' });
    payment.amount = '5000.00';
    const result = await post('/payment_submit', {
      headers: apiHeaders(),
      body: payment,
    });
    assertNoRelay(result);
    assert.equal(result.status, 400);
    assert.deepEqual(JSON.parse(result.text), { error: 'Invalid payment' });
  });

  test('valid credentials do not relay extra fields that were not covered by the signature', async () => {
    const payment = signedPayment();
    payment.card_number = 'test-card-placeholder';
    const result = await post('/payment_submit', {
      headers: apiHeaders(),
      body: payment,
    });
    assertNoRelay(result);
    assert.equal(result.status, 400);
    assert.deepEqual(JSON.parse(result.text), { error: 'Invalid payment' });
  });

  test('valid credentials relay only the signed payment and only to the pay host', async () => {
    const payment = signedPayment();
    const result = await post('/payment_submit', {
      headers: apiHeaders(),
      body: payment,
    });
    assert.equal(result.status, 200);
    assert.equal(result.outbound.length, 1);
    const call = result.outbound[0];
    assert.equal(call.protocol, 'https:');
    assert.equal(call.hostname, PAY_HOST);
    assert.equal(call.path, PAY_PATH);
    assert.equal((call.method || 'POST').toUpperCase(), 'POST');
    assert.deepEqual(qs.parse(call.body), payment);
  });
});
