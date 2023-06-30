const functions = require('firebase-functions');
const app = require('./app');

exports.cybersource = functions.region('us-east1').https.onRequest(app);
