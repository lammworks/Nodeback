'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const querystring = require('node:querystring');
const { after, before, test } = require('node:test');

const repoRoot = path.resolve(__dirname, '..', '..');
const functionsDir = path.join(repoRoot, 'functions');
const CREDENTIAL_NAMES = ['ACCESS_KEY', 'PROFILE_ID', 'SIGNATURE', 'API_KEY', 'API_SECRET'];
const PLACEHOLDER_VALUES = new Set([
  'placeholder',
  'changeme',
  'example',
  'your-secret',
  'your_secret',
  'test',
  'dummy',
  'xxx',
  'replace-me',
  'todo',
  'sample',
  'secret',
  'password',
  'placeholder-api-key',
  'placeholder-api-secret',
  'placeholder-signature',
  'placeholder-access-key',
  'placeholder-profile-id',
]);

function isPlaceholder(value) {
  const trimmed = String(value == null ? '' : value).trim();
  if (!trimmed || trimmed.length < 8) {
    return true;
  }
  return PLACEHOLDER_VALUES.has(trimmed.toLowerCase());
}

function trackedFiles() {
  const out = execFileSync('git', ['ls-files', '-z'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  return out.split('\0').filter(Boolean);
}

function extractCredentialValues(text) {
  const found = Object.fromEntries(CREDENTIAL_NAMES.map((name) => [name, []]));
  for (const name of CREDENTIAL_NAMES) {
    const patterns = [
      new RegExp('(?:^|\\n)\\s*(?:export\\s+)?' + name + '\\s*=\\s*([^\\s#]+)', 'g'),
      new RegExp('"' + name + '"\\s*:\\s*"([^"]*)"', 'g'),
    ];
    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(text)) !== null) {
        let value = match[1].trim();
        if (
          (value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))
        ) {
          value = value.slice(1, -1);
        }
        if (!isPlaceholder(value) && !found[name].includes(value)) {
          found[name].push(value);
        }
      }
    }
  }
  return found;
}

function trackedBlob(rel) {
  try {
    return execFileSync('git', ['show', ':' + rel], {
      cwd: repoRoot,
      maxBuffer: 20 * 1024 * 1024,
    });
  } catch (error) {
    return null;
  }
}

function credentialsInTrackedTree() {
  const values = Object.fromEntries(CREDENTIAL_NAMES.map((name) => [name, []]));
  const files = [];
  for (const rel of trackedFiles()) {
    const data = trackedBlob(rel);
    if (!data || data.includes(0)) {
      continue;
    }
    const extracted = extractCredentialValues(data.toString('utf8'));
    let hit = false;
    for (const name of CREDENTIAL_NAMES) {
      for (const value of extracted[name]) {
        if (!values[name].includes(value)) {
          values[name].push(value);
        }
        hit = true;
      }
    }
    if (hit) {
      files.push(rel);
    }
  }
  return { values, files };
}

// Same field order and HMAC the checkout route uses in functions/app.js.
function signData(paymentDetails, secretKey) {
  const fieldOrder = String(paymentDetails.signed_field_names || '').split(',');
  const data = fieldOrder.map((field) => field + '=' + paymentDetails[field]).join(',');
  return crypto.createHmac('sha256', secretKey).update(data).digest('base64');
}

function sameSignature(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  if (a.length === 0 || a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

function postJson(port, headers, body) {
  const payload = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: '/payment_form',
        method: 'POST',
        headers: Object.assign(
          {
            'content-type': 'application/json',
            'content-length': String(payload.length),
          },
          headers
        ),
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let parsed = null;
          try {
            parsed = JSON.parse(raw);
          } catch (error) {
            parsed = null;
          }
          resolve({ status: res.statusCode, body: parsed });
        });
      }
    );
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

function attackerBody() {
  const amount = String(100 + (crypto.randomBytes(1)[0] % 50)) + '.50';
  const reference = 'attacker-order-' + crypto.randomBytes(4).toString('hex');
  return {
    amount,
    reference_number: reference,
    bill_to_address_line1: '1 Attacker Street',
    bill_to_address_city: 'Panama',
    bill_to_email: 'attacker@example.com',
    bill_to_forename: 'Alex',
    bill_to_surname: 'Rider',
    req_tax_amount: '0.00',
    access_key: 'attacker-supplied-access-key',
    profile_id: 'attacker-supplied-profile',
    transaction_type: 'authorization',
    currency: 'EUR',
  };
}

function responseForgesSale(response, body, secrets) {
  if (!response || response.status !== 200 || !response.body) {
    return false;
  }
  if (!response.body.paymentUrl || !response.body.signature) {
    return false;
  }
  const query = String(response.body.paymentUrl).split('?')[1] || '';
  const fields = querystring.parse(query);
  const attackerFieldsKept =
    fields.amount === body.amount &&
    fields.reference_number === body.reference_number &&
    fields.bill_to_email === body.bill_to_email &&
    fields.bill_to_forename === body.bill_to_forename &&
    fields.bill_to_surname === body.bill_to_surname &&
    fields.transaction_type === 'sale,create_payment_token' &&
    fields.currency === 'USD' &&
    fields.access_key !== 'attacker-supplied-access-key' &&
    fields.profile_id !== 'attacker-supplied-profile';
  if (!attackerFieldsKept) {
    return false;
  }
  return secrets.some((secret) => sameSignature(response.body.signature, signData(fields, secret)));
}

let server;
let port;

before(async () => {
  for (const name of CREDENTIAL_NAMES) {
    delete process.env[name];
  }
  delete process.env.DOTENV_KEY;
  process.chdir(functionsDir);
  console.log = () => {};
  console.info = () => {};
  console.warn = () => {};
  console.error = () => {};
  const loaded = require(path.join(functionsDir, 'index.js'));
  server = http.createServer((req, res) => {
    loaded.cybersource(req, res);
  });
  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  port = server.address().port;
});

after(async () => {
  if (!server) {
    return;
  }
  await new Promise((resolve) => server.close(resolve));
});

test('functions/.env is not tracked', () => {
  assert.equal(
    trackedFiles().includes('functions/.env'),
    false,
    'functions/.env is tracked, so repository readers receive the checkout credentials'
  );
});

test('functions/.gitignore excludes the checkout environment file', () => {
  const gitignorePath = path.join(functionsDir, '.gitignore');
  const text = fs.existsSync(gitignorePath) ? fs.readFileSync(gitignorePath, 'utf8') : '';
  const covers = text.split(/\n/).some((line) => {
    const trimmed = line.trim();
    return (
      trimmed === '.env' ||
      trimmed === '/.env' ||
      trimmed === '**/.env' ||
      trimmed === '.env*' ||
      trimmed === '*.env'
    );
  });
  assert.equal(covers, true, 'functions/.gitignore does not exclude .env');
});

test('tracked files do not contain checkout credential material', () => {
  const leaked = credentialsInTrackedTree();
  assert.deepEqual(
    leaked.files,
    [],
    'tracked files still publish checkout credentials: ' + leaked.files.join(', ')
  );
});

test('callers without both API headers are rejected', async () => {
  const response = await postJson(port, {}, attackerBody());
  assert.equal(response.status, 401);
});

test('a placeholder API key pair is rejected', async () => {
  const response = await postJson(
    port,
    {
      'x-api-key': 'placeholder-api-key',
      'x-api-secret': 'placeholder-api-secret',
    },
    attackerBody()
  );
  assert.equal(response.status, 401);
});

test('repository API keys are rejected unless the matching API secret is also presented', async () => {
  const leaked = credentialsInTrackedTree();
  const apiKeys = leaked.values.API_KEY.length ? leaked.values.API_KEY : ['placeholder-api-key'];
  for (const apiKey of apiKeys) {
    const response = await postJson(
      port,
      {
        'x-api-key': apiKey,
        'x-api-secret': 'placeholder-api-secret',
      },
      attackerBody()
    );
    assert.notEqual(
      response.status,
      200,
      'the checkout route signed a sale with a repository API key and a stand-in API secret'
    );
  }
});

test('repository API secrets are rejected unless the matching API key is also presented', async () => {
  const leaked = credentialsInTrackedTree();
  const apiSecrets = leaked.values.API_SECRET.length
    ? leaked.values.API_SECRET
    : ['placeholder-api-secret'];
  for (const apiSecret of apiSecrets) {
    const response = await postJson(
      port,
      {
        'x-api-key': 'placeholder-api-key',
        'x-api-secret': apiSecret,
      },
      attackerBody()
    );
    assert.notEqual(
      response.status,
      200,
      'the checkout route signed a sale with a repository API secret and a stand-in API key'
    );
  }
});

test('repository readers cannot have the checkout route sign an attacker-chosen sale', async () => {
  const leaked = credentialsInTrackedTree();
  const apiKeys = leaked.values.API_KEY.length ? leaked.values.API_KEY : ['placeholder-api-key'];
  const apiSecrets = leaked.values.API_SECRET.length
    ? leaked.values.API_SECRET
    : ['placeholder-api-secret'];
  const secrets = leaked.values.SIGNATURE.slice();
  if (process.env.SIGNATURE && !isPlaceholder(process.env.SIGNATURE) && !secrets.includes(process.env.SIGNATURE)) {
    secrets.push(process.env.SIGNATURE);
  }
  const body = attackerBody();
  let forged = false;
  let accepted = false;
  for (const apiKey of apiKeys) {
    for (const apiSecret of apiSecrets) {
      const response = await postJson(
        port,
        {
          'x-api-key': apiKey,
          'x-api-secret': apiSecret,
        },
        body
      );
      if (response.status === 200) {
        accepted = true;
      }
      if (responseForgesSale(response, body, secrets)) {
        forged = true;
      }
    }
  }
  assert.equal(
    forged,
    false,
    'POST /payment_form produced a Secure Acceptance signature over attacker amount ' +
      body.amount +
      ' reference ' +
      body.reference_number +
      ' using an HMAC secret from tracked files (' +
      leaked.files.join(', ') +
      ')'
  );
  assert.equal(
    accepted,
    false,
    'POST /payment_form accepted credentials found in tracked files (' +
      leaked.files.join(', ') +
      ') and returned a payment response'
  );
});

test('a repository HMAC secret cannot sign an arbitrary Secure Acceptance sale', () => {
  const leaked = credentialsInTrackedTree();
  const amount = '25.00';
  const reference = 'attacker-order-local';
  let offlineForged = false;
  for (const secret of leaked.values.SIGNATURE) {
    const fields = {
      access_key: leaked.values.ACCESS_KEY[0] || 'placeholder-access-key',
      profile_id: leaked.values.PROFILE_ID[0] || 'placeholder-profile-id',
      transaction_uuid: 'attacker-transaction',
      unsigned_field_names: '',
      signed_date_time: '2020-01-01T00:00:00Z',
      locale: 'en',
      transaction_type: 'sale,create_payment_token',
      reference_number: reference,
      amount,
      currency: 'USD',
    };
    fields.signed_field_names = [
      'access_key',
      'profile_id',
      'transaction_uuid',
      'signed_field_names',
      'unsigned_field_names',
      'signed_date_time',
      'locale',
      'transaction_type',
      'reference_number',
      'amount',
      'currency',
    ].join(',');
    const signature = signData(fields, secret);
    if (
      fields.amount === amount &&
      fields.reference_number === reference &&
      fields.transaction_type === 'sale,create_payment_token' &&
      sameSignature(signature, signData(fields, secret))
    ) {
      offlineForged = true;
    }
  }
  assert.equal(
    offlineForged,
    false,
    'a Secure Acceptance HMAC secret is present in tracked files: ' + leaked.files.join(', ')
  );
});
