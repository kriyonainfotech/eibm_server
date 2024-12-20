const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  phone: {
    type: String,
    sparse: true,  // Only enforce uniqueness for non-null values
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  password: {
    type: String,
  },
  resetPasswordToken: {
    type: String
  },
  resetPasswordExpires: {
    type: Date
  },
  profilePic: { 
    type: String,
    default: 'default.avif'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  role: { type: String, default: 'user' },
  AdmissionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AdmissionForm',
  },
  status: { 
    type: String, 
    default: 'Pending'
  },
  purchaseStatus : {
    type: String,
    default: 'Not Purchased'
  }
});

module.exports = mongoose.model('User', userSchema);

