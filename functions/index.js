const functions = require('firebase-functions');
const app = require('./app');

// Values come from Cloud Secret Manager (`firebase functions:secrets:set <NAME>`), never from a committed file.
const PAYMENT_SECRETS = ['ACCESS_KEY', 'PROFILE_ID', 'SIGNATURE', 'API_KEY', 'API_SECRET'];

exports.cybersource = functions
  .runWith({ secrets: PAYMENT_SECRETS })
  .region('us-east1')
  .https.onRequest(app);
