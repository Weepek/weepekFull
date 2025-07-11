const express = require('express');
const {
  getMe,
  updateDetails,
  updatePassword
} = require('../controllers/userController');
const { protect } = require('../middleware/auth');
const { check } = require('express-validator');

const router = express.Router();

router.use(protect);

router.get('/me', getMe);

router.put(
  '/me',
  [
    check('username', 'Username is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail()
  ],
  updateDetails
);

router.put(
  '/updatepassword',
  [
    check('currentPassword', 'Current password is required').not().isEmpty(),
    check('newPassword', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
  ],
  updatePassword
);

module.exports = router;