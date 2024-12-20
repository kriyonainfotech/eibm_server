const bcrypt = require('bcrypt')

const hashPassword = async(password) => {
    try {
        const saltrounds = 12;
    const hashedpassword = await bcrypt.hash(password,saltrounds)
    console.log(hashedpassword);
    
    return hashedpassword 
    } catch (error) {
        console.log(error);
    }
}
const comparePassword = async(password,hashedpassword) => {
    try {
        return await bcrypt.compare(password,hashedpassword)
    } catch (error) {
        console.log(error);
    }
}
module.exports = {hashPassword,comparePassword}