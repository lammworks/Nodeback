// Import necessary modules
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const querystring = require('querystring');

// Initialize Express app
const app = express();

// Use necessary middleware
app.use(cors());
app.use(helmet());
app.use(bodyParser.json());

// Set up rate limiting
const limiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 24 hours
  max: 10, // limit each IP to 10 requests per windowMs
  keyGenerator: function (req, res) {
    return req.headers['fastly-client-ip'] || req.ip; // Use 'fastly-client-ip' header, fall back to req.ip
  }
});

// Apply the rate limit to all requests
app.use(limiter);

// Function to generate a random string for transaction UUID
function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-';
  let randomString = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    randomString += characters[randomIndex];
  }
  return randomString;
}

// Function to sign the payment details using HMAC
function signData(paymentDetails, secretKey) {
  const fieldOrder = paymentDetails.signed_field_names.split(',');
  const kvPairs = fieldOrder.map(field => `${field}=${paymentDetails[field]}`);
  const data = kvPairs.join(',');
  return crypto.createHmac('sha256', secretKey).update(data).digest('base64');
}

// Route to handle payment form submission
app.post('/payment_form', async (req, res, next) => {
  try {
    let paymentDetails = req.body;
    let date = new Date();
    let isoString = date.toISOString();
    let isoStringWithoutMilliseconds = isoString.slice(0,19)+'Z';

    // Set necessary fields for payment
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

    // Sign the payment details
    const signature = signData(paymentDetails, process.env.SIGNATURE);
    paymentDetails.signature = signature;

    // Make a POST request to the Cybersource payment gateway
    const cybersourceResponse = await axios.post('https://testsecureacceptance.cybersource.com/pay', querystring.stringify(paymentDetails), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    // Return the response from the Cybersource payment gateway
    res.send(cybersourceResponse.data);
  } catch (err) {
    // Pass the error to the next middleware function
    next(err);
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  // Log the error stack trace
  console.error(err.stack);
  // Send a 500 response to the client
  res.status(500).send('Something broke!');
});

// Export the app module
<<<<<<< HEAD
module.exports = app;
=======
module.exports = app;
>>>>>>> 197f0464f18cb684c63b6d8e446e037ec852a8da
