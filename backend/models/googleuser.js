const mongoose = require('mongoose');

const GoogleuserSchema = new mongoose.Schema({
  uid: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  profilePic: { type: String },
  phone: { type: String }, // Optional
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
}, { timestamps: true });

module.exports = mongoose.model('GoogleUser', GoogleuserSchema);

