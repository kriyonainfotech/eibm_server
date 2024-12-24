const mongoose = require("mongoose");
const ConnectDb = async () => {
  try {
    const db = await mongoose.connect(
      "mongodb+srv://eibm:eibm@cluster0.zbfjd.mongodb.net/eibm",
      {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        socketTimeoutMS: 45000, // Increase timeout
        connectTimeoutMS: 30000, // Increase connection timeout
      }
    );
    console.log(`Mongodb Connected : --  ${db.connection.host}`);
  } catch (error) {
    console.log(error);
  }
};
module.exports = ConnectDb;
