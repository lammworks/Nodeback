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
const qs = require('qs'); // Add this at the top of your file

// Initialize Express app
const app = express();

// Use necessary middleware
app.use(cors());
app.use(helmet());
app.use(bodyParser.json());

// Set up rate limiting
const limiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 24 hours
  max: 100, // limit each IP to 10 requests per windowMs
  keyGenerator: function (req, res) {
    return req.headers['x-fastly-client-ip'] || req.ip; // Use 'fastly-client-ip' header, fall back to req.ip
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

// Middleware to validate API key
function validateApiKey(req, res, next) {
  const { 'x-api-key': apiKey, 'x-api-secret': apiSecret } = req.headers;

  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  if (!apiSecret || apiSecret !== process.env.API_SECRET) {
    return res.status(401).json({ error: 'Invalid API secret' });
  }

  next();
}

// Route to handle payment form submission
app.post('/payment_form', validateApiKey, (req, res, next) => {
  try {
    let paymentDetails = req.body;
    let date = new Date();
    let isoString = date.toISOString();
    let isoStringWithoutMilliseconds = isoString.slice(0,19)+'Z';

    // Set necessary fields for payment
    paymentDetails.access_key = process.env.ACCESS_KEY;
    paymentDetails.profile_id = process.env.PROFILE_ID;
    paymentDetails.transaction_uuid = generateRandomString(50);
    paymentDetails.signed_field_names = 'access_key,profile_id,transaction_uuid,signed_field_names,unsigned_field_names,signed_date_time,locale,transaction_type,reference_number,amount,currency,bill_to_address_line1,bill_to_address_city,bill_to_address_country,bill_to_email,bill_to_forename,bill_to_surname,customer_ip_address,tax_indicator,line_item_count,item_0_total_amount,item_0_unit_price,item_0_tax_amount'; // Add new fields to the signed fields
    paymentDetails.unsigned_field_names = '';
    paymentDetails.signed_date_time = isoStringWithoutMilliseconds;
    paymentDetails.locale = 'es-es';
    paymentDetails.transaction_type = 'sale,create_payment_token';
    paymentDetails.currency = 'USD';
    paymentDetails.bill_to_address_country = 'PA';
    paymentDetails.customer_ip_address = req.ip; // Add the customer's IP address
    paymentDetails.tax_indicator = 'Y';// Always 'Y'
    paymentDetails.line_item_count = '1'; // Always '1'
    paymentDetails.item_0_total_amount = paymentDetails.amount; // Same as 'amount'
    paymentDetails.item_0_unit_price = paymentDetails.amount; // Same as 'amount'
    paymentDetails.item_0_tax_amount = paymentDetails.req_tax_amount; // Same as 'req_tax_amount'

    // Sign the payment details
    const signature = signData(paymentDetails, process.env.SIGNATURE);
    paymentDetails.signature = signature;

    // Create a URL of the frontend service with the payment initiation data as query parameters
    const frontendUrl = `https://checkout.lavanda.com.pa?${querystring.stringify(paymentDetails)}`;

    // Return the URL of the frontend service
    res.json({
      paymentUrl: frontendUrl,
      signature: signature
    });
  } catch (err) {
    // If there's an error, pass it to the next middleware function
    next(err);
  }
});

// Route to handle payment submission
app.post('/payment_submit', async (req, res, next) => {
  try {
    const paymentDetails = req.body;

    // Stringify the payment details as URL-encoded form data
    const formData = qs.stringify(paymentDetails);

    const response = await axios.post('https://testsecureacceptance.cybersource.com/pay', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    res.send(response.data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'An error occurred while submitting the payment' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Export the Express app
module.exports = app;
