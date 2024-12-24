const mongoose = require("mongoose");
const ConnectDb = async () => {
  try {
    const db = await mongoose.connect(
      "mongodb+srv://eibm:eibm@cluster0.zbfjd.mongodb.net/eibm"
    );
    console.log(`Mongodb Connected : --  ${db.connection.host}`);
  } catch (error) {
    console.log(error);
  }
};
module.exports = ConnectDb;
