const jwt = require("jsonwebtoken")
const generateAccessToken = (user) => {
    const accessToken = jwt.sign({id : user._id},"EIBMgfsjkdkfbjkhfkhwhf",{
        expiresIn: '3h'
    })
    return accessToken
}
const generateRefreshToken = (user) => {
    const refreshToken = jwt.sign({ id: user._id },"EIBMgfsjkdkfbjkhfkhwhf", {
      expiresIn: "3h",
    });
    return refreshToken;
  };
  
  const verifyAccessToken = (token) => {
    return jwt.verify(token,"EIBMgfsjkdkfbjkhfkhwhf");
  };
  
  const verifyRefreshToken = (token) => {
    return jwt.verify(token,"EIBMgfsjkdkfbjkhfkhwhf");
  };
  
  module.exports = {
    generateAccessToken,
    generateRefreshToken,
    verifyAccessToken,
    verifyRefreshToken,
  };