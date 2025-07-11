//  const express = require('express');
// const router = express.Router();
// const {
//   signup,
//   login,
//   forgotPassword,
//   resetPassword,
//   getUserDetails,
//   updateUserDetails,
// } = require('../controllers/authController');
// const authMiddleware = require('../middleware/authMiddleware');

// router.post('/signup', signup);
// router.post('/login', login);
// router.post('/forgotpassword', forgotPassword);
// router.post('/forgetpassword/:token', resetPassword);
// router.get('/userdetails', authMiddleware, getUserDetails);

// // Update user details
// router.put('/userdetails', authMiddleware, updateUserDetails);

// module.exports = router;


 
const express = require('express');
const router = express.Router();
const {
  signup,
  login,
  forgotPassword,
  resetPassword,
  getUserDetails,
  updateUserDetails,
  changePassword,
  verifyToken,
} = require('../controllers/authController');

router.post('/signup', signup);
router.post('/login', login);
router.post('/forgotpassword', forgotPassword);
router.post('/resetpassword/:token', resetPassword); // Corrected route name to match resetPassword
router.post('/changepassword', changePassword); //  
router.get('/user/details', verifyToken, getUserDetails);
router.put('/user/details', verifyToken, updateUserDetails);

module.exports = router;