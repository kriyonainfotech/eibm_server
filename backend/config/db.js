const mongoose  = require('mongoose')
const ConnectDb = async() => {
    try {
        const db = await mongoose.connect('mongodb+srv://sujaltank13:sujaltank13@cluster0.7duu8xj.mongodb.net/EIBM_APP')
        console.log(`Mongodb Connected : --  ${db.connection.host}`);
    } catch (error) {
        console.log(error);
    }
}
module.exports = ConnectDb