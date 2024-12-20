const mongoose = require('mongoose');

const admissionFormSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.Mixed, // Mixed type to store different ID formats
    refPath: 'userModel', // Dynamic reference
    required: true
  },
  userModel: {
    type: String,
    required: true,
    enum: ['User', 'GoogleUser'] // Possible models for reference
  },
  name: {
    type: String,
    required: true
  },
  phone: {
    type: String,
    required: true,
    unique: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  city: {
    type: String,
    required: true
  },
  address: {
    type: String,
    required: true
  },
  permanetaddress: {
    type: String,
    required: true
  },
  altphone: {
    type: String,
    required: true
  },
  batch:{
    type:String,
    required:true
  },
  branch: {
    type: String,
    required: true
  },
  occupation: {
    type: String,
    required: true
  },
  qualification:{
    type:String,
    required:true
  },
  date:{
    type:Date,
    required:true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});
module.exports = mongoose.model('AdmissionForm', admissionFormSchema);