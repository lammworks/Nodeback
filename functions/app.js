require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(cors());
app.use(helmet());
app.use(bodyParser.json());

const limiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 24 hours
  max: 10, // limit each IP to 10 requests per windowMs
  keyGenerator: function (req, res) {
  return req.headers['fastly-client-ip'] || req.ip; // Use 'fastly-client-ip' header, fall back to req.ip
  }
});

// Apply the rate limit to all requests
app.use(limiter);

function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-';
  let randomString = '';
  for (let i = 0; i < length; i++) {
  const randomIndex = Math.floor(Math.random() * characters.length);
  randomString += characters[randomIndex];
  }
  return randomString;
}

function signData(paymentDetails, secretKey) {
  const fieldOrder = paymentDetails.signed_field_names.split(',');
  const kvPairs = fieldOrder.map(field => `${field}=${paymentDetails[field]}`);
  const data = kvPairs.join(',');
  return crypto.createHmac('sha256', secretKey).update(data).digest('base64');
}

app.post('/payment_form', (req, res, next) => {
  try {
  let paymentDetails = req.body;
  let date = new Date();
  let isoString = date.toISOString();
  let isoStringWithoutMilliseconds = isoString.slice(0,19)+'Z';

  paymentDetails.access_key = process.env.ACCESS_KEY;
  paymentDetails.profile_id = process.env.PROFILE_ID;
  paymentDetails.transaction_uuid = generateRandomString(50);
  paymentDetails.signed_field_names = 'access_key,profile_id,transaction_uuid,signed_field_names,unsigned_field_names,signed_date_time,locale,transaction_type,reference_number,amount,currency,bill_to_address_line1,bill_to_address_city,bill_to_address_country,bill_to_email,bill_to_forename,bill_to_surname,req_tax_amount';
  paymentDetails.unsigned_field_names = '';
  paymentDetails.signed_date_time = isoStringWithoutMilliseconds;
  paymentDetails.locale = 'es-es';
  paymentDetails.transaction_type = 'sale,create_payment_token';
  paymentDetails.currency = 'USD';
  paymentDetails.bill_to_address_country = 'PA';

  const signature = signData(paymentDetails, process.env.SIGNATURE);
  paymentDetails.signature = signature;

  res.json({
    paymentDetails: paymentDetails,
    signature: signature
  });
  } catch (err) {
  next(err);
  }
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

module.exports = app;