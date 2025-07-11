//  const mongoose = require('mongoose');

// const userSchema = new mongoose.Schema({
//   name: String,
//   email: { type: String, unique: true },
//   number: String,
//   address: String,
//   state: String,      
//   country: String,
//   postalCode: String,
//   password: String,
//   resetToken: String,
//   resetTokenExpiry: Date
// });

// module.exports = mongoose.model('User', userSchema);
 
 const mongoose = require('mongoose');

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  number: { type: String },
  address: { type: String },
  state: { type: String },
  country: { type: String },
  postalCode: { type: String }
});
module.exports = mongoose.model('User', userSchema);