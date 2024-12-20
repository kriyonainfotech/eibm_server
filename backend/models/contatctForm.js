// models/ContactForm.js
const mongoose = require("mongoose");

const contactFormSchema = new mongoose.Schema({
  name: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String, required: true },
  purpose: { type: String, required: true },
  address: { type: String },
  status: {
    type: String,
    enum: ['Pending', 'Call Not Receive','Not Confirmed', 'Delay','Converted','Cancel'], // Added "Converted" as an option
    default: 'Pending', // Set default status
  },
  paymentStatus: {
    type: String,
    enum: ['Pending', 'Complete'],
    default: 'Pending'  // Default to 'Pending' if not provided
  },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("ContactForm", contactFormSchema);
