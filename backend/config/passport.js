// const passport = require('passport');
// const dotenv = require('dotenv')
// dotenv.config()
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const jwt = require('jsonwebtoken');
// const UserModel = require('../models/user'); // Assume you have a User model
// const { generateAccessToken, generateRefreshToken } = require('../lib/token');
// passport.use(new GoogleStrategy({
//     clientID: process.env.GOOGLE_CLIENT_ID,
//     clientSecret: process.env.GOOGLE_CLIENT_SECRET,
//     callbackURL: '/auth/google/callback',
//     scope : ["profile","email"]
// }, async (accessToken, refreshToken, profile, done) => {
//     let user = await UserModel.findOne({ googleId: profile.id });
//     if (!user) {
//         user = new UserModel({
//             googleId: profile.id,
//             name: profile.displayName,
//             email: profile.emails[0].value,
//             avatar: profile.photos[0].value
//         });
//         await user.save()
//     }

//     const tokenData = {
//         accessToken: generateAccessToken(user),
//         refreshToken: generateRefreshToken(user)
//     };  
//     // res.cookie("accessToken", accessToken, {
//     //     httpOnly: true,
//     //     sameSite: "None",
//     //     secure: true,
//     //     maxAge: 24 * 60 * 60 * 1000, // 1 day
//     // })
//     // .cookie("refreshToken", refreshToken, {
//     //     httpOnly: true,
//     //     sameSite: "None",
//     //     secure: true,
//     //     maxAge: 24 * 60 * 60 * 1000, // 1 day
//     // })
//     // .status(201).json({
//     //     message: "REGISTRATION SUCCESSFUL"
//     // });
//     return done(null, { user, tokenData });
// }));

// passport.serializeUser((user, done) => {
//     done(null, user);
// });

// passport.deserializeUser((obj, done) => {
//     done(null, obj);
// });
// module.exports = passport