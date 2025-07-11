const mongoose = require('mongoose');

const userDetailsSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  phone: String,
  address: String,
  city: String,
  country: String,
  postalCode: String,
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('UserDetails', userDetailsSchema);