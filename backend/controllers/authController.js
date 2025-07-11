// const User = require('../models/User');
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');
// const crypto = require('crypto');
// const sendEmail = require('../utils/sendEmail');

// exports.signup = async (req, res) => {
//   const { name, email, password } = req.body;
//   try {
//     const existingUser = await User.findOne({ email });
//     if (existingUser) return res.status(400).json({ error: 'Email already in use' });

//     const hashed = await bcrypt.hash(password, 10);
//     const user = await User.create({ name, email, password: hashed });

//     res.status(201).json({ message: 'User created' });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: 'Signup failed' });
//   }
// };

// // Login
// exports.login = async (req, res) => {
//   const { email, password } = req.body;
//   try {
//     const user = await User.findOne({ email });
//     if (!user || !(await bcrypt.compare(password, user.password)))
//       return res.status(401).json({ error: 'Invalid credentials' });

//     const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, {
//       expiresIn: process.env.JWT_EXPIRES_IN
//     });

//     res.json({ token });
//   } catch (err) {
//     res.status(500).json({ error: 'Server error' });
//   }
// };
// // Forgot Password
// exports.forgotPassword = async (req, res) => {
//   const { email } = req.body;
//   try {
//     const user = await User.findOne({ email });
//     if (!user) return res.status(404).json({ error: 'User not found' });

//     const token = crypto.randomBytes(32).toString('hex');
//     user.resetToken = token;
//     user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
//     await user.save();

//     const resetLink = `http://localhost:5173/weepek/ResetPassword/${token}`;
//     await sendEmail(email, 'Password Reset', `Reset here: ${resetLink}`);

//     res.json({ message: 'Reset link sent' });
//   } catch (err) {
//     res.status(500).json({ error: 'Failed to send reset email' });
//   }
// };

// // Reset Password
// exports.resetPassword = async (req, res) => {
//   const { token } = req.params;
//   const { password } = req.body;

//   try {
//     const user = await User.findOne({
//       resetToken: token,
//       resetTokenExpiry: { $gt: Date.now() }
//     });

//     if (!user) return res.status(400).json({ error: 'Invalid or expired token' });

//     user.password = await bcrypt.hash(password, 10);
//     user.resetToken = undefined;
//     user.resetTokenExpiry = undefined;
//     await user.save();

//     res.json({ message: 'Password reset successful' });
//   } catch (err) {
//     res.status(500).json({ error: 'Failed to reset password' });
//   }
// };

// // Change Password (still uses authMiddleware)
// exports.changePassword = async (req, res) => {
//   try {
//     const user = await User.findOne({ email: req.userEmail });
//     if (!user) return res.status(404).json({ error: 'User not found' });

//     const isMatch = await bcrypt.compare(req.body.currentPassword, user.password);
//     if (!isMatch) return res.status(401).json({ error: 'Current password is incorrect' });

//     user.password = await bcrypt.hash(req.body.newPassword, 10);
//     await user.save();

//     res.json({ message: 'Password changed successfully' });
//   } catch (err) {
//     res.status(500).json({ error: 'Failed to change password' });
//   }
// };

// // GET user details (no authMiddleware, uses email from request body)
// exports.getUserDetails = async (req, res) => {
//   const { email } = req.body;
//   if (!email) return res.status(400).json({ error: 'Email is required' });

//   try {
//     const user = await User.findOne({ email }).select('-password -resetToken -resetTokenExpiry');
//     if (!user) return res.status(404).json({ error: 'User not found' });

//     res.json(user);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: 'Failed to fetch user details' });
//   }
// };

// // UPDATE user details (no authMiddleware, uses email from request body)
// exports.updateUserDetails = async (req, res) => {
//   const { email, name, phone, address, city, country, postalCode } = req.body;
//   if (!email) return res.status(400).json({ error: 'Email is required' });

//   try {
//     const user = await User.findOne({ email });
//     if (!user) return res.status(404).json({ error: 'User not found' });

//     user.name = name || user.name;
//     user.number = phone || user.number;
//     user.address = address || user.address;
//     user.state = city || user.state;
//     user.country = country || user.country;
//     user.postalCode = postalCode || user.postalCode;

//     await user.save();

//     res.json({ message: 'User details updated successfully!' });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: 'Failed to update user details' });
//   }
// };
 

// exports.signup = async (req, res) => {
//   const { name, email, password } = req.body;
//   try {
//     const existingUser = await User.findOne({ email });
//     if (existingUser) return res.status(400).json({ error: 'Email already in use' });

//     const hashed = await bcrypt.hash(password, 10);
//     const user = await User.create({ name, email, password: hashed });

//     res.status(201).json({ message: 'User created' });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: 'Signup failed' });
//   }
// };

// exports.login = async (req, res) => {
//   const { email, password } = req.body;
//   try {
//     const user = await User.findOne({ email });
//     if (!user || !(await bcrypt.compare(password, user.password)))
//       return res.status(401).json({ error: 'Invalid credentials' });

//     const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
//       expiresIn: process.env.JWT_EXPIRES_IN
//     });

//     res.json({ token });
//   } catch (err) {
//     res.status(500).json({ error: 'Server error' });
//   }
// };

// exports.forgotPassword = async (req, res) => {
//   const { email } = req.body;
//   try {
//     const user = await User.findOne({ email });
//     if (!user) return res.status(404).json({ error: 'User not found' });

//     const token = crypto.randomBytes(32).toString('hex');
//     user.resetToken = token;
//     user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
//     await user.save();

//     const resetLink = `http://localhost:5173/weepek/ResetPassword/${token}`;
//     await sendEmail(email, 'Password Reset', `Reset here: ${resetLink}`);

//     res.json({ message: 'Reset link sent' });
//   } catch (err) {
//     res.status(500).json({ error: 'Failed to send reset email' });
//   }
// };

// exports.resetPassword = async (req, res) => {
//   const { token } = req.params;
//   const { password } = req.body;

//   try {
//     const user = await User.findOne({
//       resetToken: token,
//       resetTokenExpiry: { $gt: Date.now() }
//     });

//     if (!user) return res.status(400).json({ error: 'Invalid or expired token' });

//     user.password = await bcrypt.hash(password, 10);
//     user.resetToken = undefined;
//     user.resetTokenExpiry = undefined;
//     await user.save();

//     res.json({ message: 'Password reset successful' });
//   } catch (err) {
//     res.status(500).json({ error: 'Failed to reset password' });
//   }
// };

// exports.changePassword = async (req, res) => {
//   try {
//     const user = await User.findById(req.userId);
//     if (!user) return res.status(404).json({ error: 'User not found' });

//     const isMatch = await bcrypt.compare(req.body.currentPassword, user.password);
//     if (!isMatch) return res.status(401).json({ error: 'Current password is incorrect' });

//     user.password = await bcrypt.hash(req.body.newPassword, 10);
//     await user.save();

//     res.json({ message: 'Password changed successfully' });
//   } catch (err) {
//     res.status(500).json({ error: 'Failed to change password' });
//   }
// };

// // GET user details
// exports.getUserDetails = async (req, res) => {
//   try {
//     const user = await User.findById(req.userId).select('-password -resetToken -resetTokenExpiry');
//     if (!user) return res.status(404).json({ error: 'User not found' });

//     res.json(user);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: 'Failed to fetch user details' });
//   }
// };

// // UPDATE user details
// exports.updateUserDetails = async (req, res) => {
//   const { name, phone, address, city, country, postalCode } = req.body;

//   try {
//     const user = await User.findById(req.userId);
//     if (!user) return res.status(404).json({ error: 'User not found' });

//     user.name = name || user.name;
//     user.number = phone || user.number;
//     user.address = address || user.address;
//     user.state = city || user.state;
//     user.country = country || user.country;
//     user.postalCode = postalCode || user.postalCode;

//     await user.save();

//     res.json({ message: 'User details updated successfully!' });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: 'Failed to update user details' });
//   }
// };
  

 const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sendEmail = require('../utils/sendEmail');

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Signup
exports.signup = async (req, res) => {
  const { name, email, password } = req.body;
  try {
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Email already in use' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashed });

    res.status(201).json({ message: 'User created' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Signup failed' });
  }
};

// Login
exports.login = async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '1d',
    });

    res.json({ token, user: { name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
};

// Forgot Password
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    if (!email) return res.status(400).json({ error: 'Email is required' });
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const token = crypto.randomBytes(32).toString('hex');
    user.resetToken = token;
    user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
    await user.save();

    const resetLink = `http://localhost:5173/weepek/ResetPassword/${token}`;
    await sendEmail(email, 'Password Reset', `Reset here: ${resetLink}`);

    res.json({ message: 'Reset link sent' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send reset email' });
  }
};

// Reset Password
exports.resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    if (!password) return res.status(400).json({ error: 'Password is required' });
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() },
    });

    if (!user) return res.status(400).json({ error: 'Invalid or expired token' });

    user.password = await bcrypt.hash(password, 10);
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
};

// Change Password
exports.changePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  try {
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required' });
    }
    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Current password is incorrect' });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to change password' });
  }
};

// Get User Details
exports.getUserDetails = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email }).select('-password -resetToken -resetTokenExpiry');
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch user details' });
  }
};

// Update User Details
exports.updateUserDetails = async (req, res) => {
  const { name, number, address, state, country, postalCode } = req.body;
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.name = name || user.name;
    user.number = number || user.number;
    user.address = address || user.address;
    user.state = state || user.state;
    user.country = country || user.country;
    user.postalCode = postalCode || user.postalCode;

    await user.save();

    res.json({ message: 'User details updated successfully', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update user details' });
  }
};

exports.verifyToken = verifyToken;