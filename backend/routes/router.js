const express = require('express')
const router = express.Router()
// const passport = require('../config/passport')
const UserModel = require('../models/user');
const googlemodel = require('../models/googleuser')
const AdmissionForm = require('../models/admission')
const BlogModel = require('../models/blogs')
const contactModel  = require('../models/contatctForm')
const crypto = require('crypto')
const multer = require('multer')
const path = require('path')
const axios = require('axios')
const jwt = require('jsonwebtoken')
const nodemailer = require('nodemailer')
const cookieParser = require('cookie-parser')
const { hashPassword, comparePassword } = require('../helpers/hashedpassword');
const { generateAccessToken, generateRefreshToken } = require('../lib/token');  
const { checkAuthenticated, checkAdmissionExists, isAdmin, isUserSuccess } = require('../middlewares/authMiddleware');

router.use(cookieParser())
router.post('/signup',async(req,res)=>{
    try {
        console.log(req.body);
        
        const { name,phone,email, password } = req.body;
        const availableAccessToken = req?.cookies?.accessToken
        const availableRefreshToken = req?.cookies?.refreshToken

        if(availableAccessToken || availableRefreshToken){
            return res.status(400).json({ message: "You are already logged in" });
        }
        const user = await UserModel.findOne({ email });
        if (user) {
            return res.status(400).json({ message: "Email already exists" });
        }
        const phonePattern = /^\d{10}$/;
            if (!phonePattern.test(phone)) {
                return res.status(400).json({
                    message: "Invalid Mobile Number"
                  });
            }
        // const passwordPattern = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
        // if (!passwordPattern.test(password)) {
        //     return res.status(400).json({
        //       message: "Password must be at least 8 characters long and include at least one number, one uppercase and one lowercase letter."
        //     });
        //   }
        const hashedPassword = await hashPassword(password)
        
        
        const savedata = new UserModel({
            name, email,phone, password: hashedPassword,
        });
    
        await savedata.save();
      
        
        const accessToken =  generateAccessToken(savedata);
        const refreshToken =  generateRefreshToken(savedata);
        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            sameSite: "None",
            secure: true,
            maxAge: 3 * 60 * 60 * 1000 // 3 hours in milliseconds
        });
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            sameSite: "None",
            secure: true,
            maxAge: 3 * 60 * 60 * 1000 // 3 hours in milliseconds
        });
        res.status(201).json({
            message: "REGISTRATION SUCCESSFUL"
        });
    } catch (error) {
        res.status(500).json({
            message: error.message
        });
    }
})
router.post('/login', async (req, res) => {
    try {
        const { email1, password1 } = req.body;
        console.log(email1);
        
        const availableAccessToken = req?.cookies?.accessToken;
        console.log(availableAccessToken);
        
        const availableRefreshToken = req?.cookies?.refreshToken;

        if (availableAccessToken || availableRefreshToken) {
            return res.status(400).json({
                message: "You are already logged in"
            });
        }

        const user = await UserModel.findOne({ email: email1 });
        if (!user) {
            return res.status(400).json({
                message: "USER DOESN'T EXIST"
            });
        }

        const checkPassword = await comparePassword(password1, user.password);
        if (checkPassword) {
            const refreshToken = req?.cookies?.refreshToken;
            if (!refreshToken) {
                let newRefreshToken = generateRefreshToken(user);
                const accessToken = generateAccessToken(user);
                res.cookie("refreshToken", newRefreshToken, {
                    httpOnly: true,
                    sameSite: "None",
                    secure:true,
                    maxAge: 3 * 60 * 60 * 1000 // 3 hours in milliseconds
                });
                res.cookie("accessToken", accessToken, {
                    httpOnly: true,
                    sameSite: "None",
                    secure: true,
                    maxAge: 3 * 60 * 60 * 1000 // 3 hours in milliseconds
                });
                user.refreshToken = newRefreshToken;
                await user.save();
            } else {
                const accessToken = generateAccessToken(user);
                res.cookie("accessToken", accessToken, {
                    httpOnly: true,
                    sameSite: "None",
                    secure: true,
                    maxAge: 3 * 60 * 60 * 1000 // 3 hours in milliseconds
                });
                console.log(res.cookie);
                
            }
            return res.status(200).json({
                message: "LOGIN SUCCESSFUL"
            });
        } else {
            res.status(401).json({
                message: "INVALID CREDENTIALS"
            });
        }
    } catch (error) {
        res.status(500).json({
            message: error.message
        });
    }
});
router.get('/logout', (req, res) => {     
    try {
       console.log(req.cookies);
       
        const availableAccessToken = req?.cookies?.accessToken;
        console.log(availableAccessToken);
        
        const availableRefreshToken = req?.cookies?.refreshToken;

        console.log("Access Token:", availableAccessToken);
        console.log("Refresh Token:", availableRefreshToken);
        if (!availableAccessToken || !availableRefreshToken) {
            return res.status(400).json({
                success: false,
                message: "You are not logged in",
            });
        }
        
        res.clearCookie('accessToken', {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
          });
          res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
          });
        res.status(200).json({
            success: true,
            message: "Logout successful",
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
});
router.get('/getuser',checkAuthenticated,async(req,res)=>{
    try {
       
       
        const userId =  req?.user?.uid 
        
        const user  = await UserModel.findById(req?.user?.id).select('-password')
        const googleuser  = await googlemodel.findOne({ uid: userId })
        if (user) {
            // If user found in UserModel, return user data
            return res.json({users:user});
        } else if (googleuser) {
            // If user found in googlemodel, return googleuser data
            return res.json({googleuser : googleuser});
        } else {
            // If no user found in either model
            return res.status(404).json({ message: "User Not Found" });
        }
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
})
// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: "sujaltank12@gmail.com",
        pass: "vfub tqcq agru bmgf"
    }
});
router.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User with given email doesn't exist" });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        console.log(user);
        

        await user.save();

        const resetUrl = `http://localhost:5173/resetpsw/?token=${resetToken}`;
        res.status(200).json({ message: 'Password reset link sent to your email'});
        const mailOptions = {
            to: user.email,
            from: 'sujaltank12@gmail.com',
            subject: 'Password Reset',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n` +
                `Please click on the following link, or paste this into your browser to complete the process:\n\n` +
                `${resetUrl}\n\n` +
                `If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };

        transporter.sendMail(mailOptions, (err) => {
            if (err) {
                return res.status(500).json({ message: err.message });
            }
            res.status(200).json({ message: 'Password reset link sent to your email' });
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});
router.post('/reset-password', async(req, res) => {
    try {
        const { token } = req.query;
        console.log(token);
        
        const { newPassword } = req.body;
        
        const user = await UserModel.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });
        
        

        if (!user) {
            return res.status(400).json({ message: 'Password reset token is invalid or has expired' });
        }
        // const passwordPattern = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
        // if (!passwordPattern.test(newPassword)) {
        //     return res.status(400).send({
        //       message: "Password must be at least 8 characters long and include at least one number, one uppercase and one lowercase letter."
        //     });
        //   }

        const hashedPassword = await hashPassword(newPassword);

        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        await user.save();

        res.status(200).json({ message: 'Password has been reset successfully' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});
const mongoose = require('mongoose')
router.post('/create-admission', checkAdmissionExists, checkAuthenticated, async (req, res) => {
    try {
        const { name, phone, email, city, address, permanetaddress, branch, batch, altphone, date, occupation, qualification } = req.body;
        let userId = req.user.uid || req.user.id;
        let userType = mongoose.Types.ObjectId.isValid(userId) ? 'User' : 'GoogleUser';
        
        const existingAdmission = await AdmissionForm.findOne({ email });
        if (existingAdmission) {
            return res.status(400).json({ message: "An admission form with this email already exists" });
        }

        const newAdmission = new AdmissionForm({
            userId,
            userModel: userType,
            name,
            phone,
            email,
            city,
            address,
            permanetaddress,
            branch,
            batch,
            altphone,
            date,
            occupation,
            qualification
        });

        if (userType === 'User') {
            const user = await UserModel.findById(userId);
            if (user) {
                user.AdmissionId = newAdmission._id;
                await user.save();
            } else {
                return res.status(404).json({ message: "User not found" });
            }
        } else if (userType === 'GoogleUser') {
            const googleUser = await googlemodel.findOne({ uid: userId });
            if (googleUser) {
                googleUser.AdmissionId = newAdmission._id;
                await googleUser.save();
            } else {
                return res.status(404).json({ message: "Google user not found" });
            }
        }

        await newAdmission.save();

        res.cookie("admissionCompleted", "true", {
            httpOnly: true,
            sameSite: "None",
            secure: true,
            maxAge: 3 * 60 * 60 * 1000 // 3 hours in milliseconds
        });
        
        res.status(201).json({
            message: "ADMISSION FORM SUBMITTED SUCCESSFULLY"
        });
    } catch (error) {
        res.status(500).json({
            message: error.message
        });
        console.log(error);
    }
});
router.get('/isadmission',checkAuthenticated,async(req,res)=>{
    try {
        const Token = req.cookies.accessToken
        if(!Token){
            return res.status(401).json({message:"Unauthorized. Please log in."})
        }
        const decoded = jwt.verify(Token, "EIBMgfsjkdkfbjkhfkhwhf"); // Replace with your
        const userId = decoded.id;
        const admissionForm = await AdmissionForm.findOne({userId});
       
        if(!admissionForm){
            return res.status(403).json({message:"You have not submitted the admission form."})
        }
        return res.status(200).json({message:"You have submitted the admission form."})
    } catch (error) {
        console.log(error);
        
    }
})  
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, './uploads')
    },
    filename: function (req, file, cb) {
      crypto.randomBytes(12,function(err,name){ 
        const fn = name.toString("hex")+path.extname(file.originalname)
        cb(null, fn)
      })

    }
})
const upload = multer({ storage: storage })
const fs = require('fs');
router.put('/updateprofile', checkAuthenticated, upload.single('image'), async (req, res) => {
    const { name, email, phone } = req.body;
    const newImage = req.file ? req.file.filename : null;

    try {
        const userId = req.user.id;
        const uid = req.user.uid;

        // Initialize the data to be updated
        const updatedata = { name, email, phone };
        if (newImage) {
            updatedata.profilePic = newImage;
        }

        // Fetch the current user to get the existing profile image
        let updateUser = await UserModel.findById(userId);

        // Check if the user exists in UserModel
        if (updateUser) {
            if (newImage && updateUser.profilePic) {
                // Construct the path to the old image
                const oldImagePath = path.join(__dirname, '..', 'uploads', updateUser.profilePic); // Adjust the path

                // Check if the old image exists before deleting
                if (fs.existsSync(oldImagePath)) {
                    fs.unlink(oldImagePath, (err) => {
                        if (err) {
                            console.error(`Failed to delete old image: ${err.message}`);
                        } else {
                            console.log('Old image deleted successfully');
                        }
                    });
                } else {
                    console.log(`Old image does not exist: ${oldImagePath}`);
                }
            }

            // Update the user's profile in UserModel
            updateUser = await UserModel.findByIdAndUpdate(userId, updatedata, { new: true });
            return res.status(200).json({ message: "Profile updated successfully in UserModel", user: updateUser });
        }

        // If user is not found in UserModel, check googlemodel
        const googleUser = await googlemodel.findOne({ uid: uid });

        if (googleUser) {
            if (newImage && googleUser.profilePic) {
                const oldImagePath = path.join(__dirname, '..', 'uploads', googleUser.profilePic);

                // Check if the old image exists before deleting
                if (fs.existsSync(oldImagePath)) {
                    fs.unlink(oldImagePath, (err) => {
                        if (err) {
                            console.error(`Failed to delete old image: ${err.message}`);
                        } else {
                            console.log('Old image deleted successfully');
                        }
                    });
                } else {
                    console.log(`Old image does not exist: ${oldImagePath}`);
                }
            }

            // Update the user's profile in googlemodel
            const updatedGoogleUser = await googlemodel.findOneAndUpdate({ uid: uid }, updatedata, { new: true });
            return res.status(200).json({ message: "Profile updated successfully in googlemodel", user: updatedGoogleUser });
        }

        return res.status(404).json({ message: "User Not Found" });
    } catch (error) {
        console.error("Error updating profile:", error.message);
        res.status(500).json({ message: 'Server error', error });
    }
});
router.get('/admin/check', isAdmin, (req, res) => {
    console.log(req.user.role);
    
    res.json({ role: req.user.role });
});
router.get('/admin/getuser', isAdmin, async (req, res) => {
    try {
        // Fetch users from UserModel who are not admins
        const usersFromUserModel = await UserModel.find({ role: { $ne: "admin" } }).select('-password'); // Exclude passwords
        
        // Fetch users from googlemodel (assuming googlemodel doesn't have an "admin" role, otherwise filter similarly)
        const usersFromGoogleModel = await googlemodel.find({ role: { $ne: "admin" } });

        // Combine results
        const allUsers = {
            usersFromUserModel,
            usersFromGoogleModel
        };
        
        // Send response
        res.status(200).json(allUsers);
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Server error" });
    }
});

const ObjectId = mongoose.Types.ObjectId;
const IsAdmissionId = async (req, res, next) => {
    try {
        const userId = req.body.id; // Make sure 'id' is correctly passed in the request body
        // console.log("Request body:", req.body);
        // console.log("User ID:", userId);

        if (!userId) {
            return res.status(400).json({ message: "User ID is required" });
        }

        let user = null;

        // Check if the userId is a valid ObjectId
        if (ObjectId.isValid(userId)) {
            user = await UserModel.findById(userId);
            // console.log("User from UserModel:", user);
        }

        if (!user) {
            // If not found in UserModel, try to find the user in the GoogleModel using uid
            user = await googlemodel.findOne({ uid: userId });
            console.log("User from GoogleModel:", user);
            
            if (!user) {
                return res.status(404).json({ message: "User not found" });
            }
        }

        if (!user.AdmissionId) {
            return res.status(403).json({ message: "User has not submitted the admission form." });
        }
        // console.log(user);
        req.admissionuser = user
        // console.log(req.admissionuser);
        
        next();
    } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).json({ message: "Error fetching user", error: error.message });
    }
};
router.post('/admin/admissionDetais', IsAdmissionId, isAdmin, async (req, res) => {
    try {
    

        let admissionForm;

        // If userId is an ObjectId, find admission form based on ObjectId
        if (mongoose.Types.ObjectId.isValid( req.admissionuser._id.toString() )) {
            admissionForm = await AdmissionForm.find({ userId: req.admissionuser._id.toString()  });
            console.log("AdmissionForm found by ObjectId:", admissionForm);
        } 
        
        // If userId is not an ObjectId, treat it as a uid and search in googlemodel
        if ((!admissionForm || admissionForm.length === 0) && req.admissionuser.uid.toString()) {
            const googleUser = await googlemodel.findOne({ uid: req.admissionuser.uid.toString() });
            console.log("Google User UID:", googleUser);

            if (googleUser) {
                admissionForm = await AdmissionForm.find({ userId: googleUser.uid });
                console.log("AdmissionForm found by UID:", admissionForm);
            }
        }

        // If no admission form is found
        if (!admissionForm) {
            return res.status(404).json({ message: "Admission form not found" });
        }

        // Return the admission form details
        res.status(200).json(admissionForm);
    } catch (error) {
        console.error("Error fetching admission form:", error);
        res.status(500).json({ message: "Error fetching admission form", error: error.message });
    }
});

router.post('/admin/updateUserStatus', isAdmin, async (req, res) => {
    const { users } = req.body;
    console.log(req.body);
    

    if (!users || !Array.isArray(users)) {
        return res.status(400).json({ message: 'Invalid request data' });
    }

    try {
        const updatePromises = users.map(user => {
            // Destructure to extract only necessary fields
            const { _id, status, purchaseStatus } = user;

            // Validate the presence of required fields
            if (!_id || !status || !purchaseStatus) {
                throw new Error(`Missing fields for user with ID: ${_id}`);
            }

            return UserModel.findByIdAndUpdate(
                _id,
                { status, purchaseStatus },
                { new: true, runValidators: true } // runValidators ensures that enums are validated
            );
        });

        const updatedUsers = await Promise.all(updatePromises);

        res.status(200).json({ message: 'Users updated successfully', users: updatedUsers });
    } catch (error) {
        console.error('Error updating users:', error.message);
        res.status(500).json({ message: 'Error updating users', error: error.message });
    }
});
router.post('/admin/toggleUserStatus', isAdmin, async (req, res) => {
    try {
      const { userId } = req.body;
  
      if (!userId) {
        return res.status(400).json({ message: 'User ID is required.' });
      }
  
      const user = await UserModel.findById(userId);
  
      if (!user) {
        return res.status(404).json({ message: 'User not found.' });
      }
  
      // Toggle status
      user.status = user.status === 'Pending' ? 'Success' : 'Pending';
  
      await user.save();
  
      res.status(200).json({
        message: `User status updated to ${user.status}.`,
        status: user.status,
      });
    } catch (error) {
      console.error('Toggle User Status Error:', error);
      res.status(500).json({ message: 'Server error while toggling user status.' });
    }
  });
router.post('/admin/updateSingleUserStatus',isAdmin,async(req,res)=>{
    try {
        const { userId, purchaseStatus } = req.body;
    
        // Validate input
        if (!userId || !['Online', 'Offline', 'Not Purchased'].includes(purchaseStatus)) {
          return res.status(400).json({ message: 'Invalid input data.' });
        }
    
        // Try updating in UserModel first
        let updatedUser = await UserModel.findByIdAndUpdate(
          userId,
          { purchaseStatus },
          { new: true, runValidators: true }
        );
    
        // If not found in UserModel, try updating in googlemodel
        if (!updatedUser) {
          updatedUser = await googlemodel.findByIdAndUpdate(
            userId,
            { purchaseStatus },
            { new: true, runValidators: true }
          );
    
          if (!updatedUser) {
            return res.status(404).json({ message: 'User not found in both models.' });
          }
        }
    
        // Respond with updated user info
        res.status(200).json({
          message: 'Purchase status updated successfully.',
          purchaseStatus: updatedUser.purchaseStatus,
          user: updatedUser,
        });
      } catch (error) {
        console.error('Single Update Error:', error);
        res.status(500).json({ message: 'Server error during single update.' });
      }
})
router.get('/admin/usercount',isAdmin,async(req, res) => {
    try {
        const successUserCount = await UserModel.countDocuments()
        const successgoogleUserCount = await googlemodel.countDocuments()
        res.json({ count: successUserCount + successgoogleUserCount });
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
});
router.get('/admin/admissioncount',isAdmin,async(req, res) => {
    try {
        const admissioncount = await AdmissionForm.countDocuments();
        res.json({ count: admissioncount });
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
}); 
router.get('/admin/coursecount',isAdmin,async(req, res) => {
    try {
        const successUserCount = await UserModel.countDocuments({ status: "Success" });
        const successgoogleUserCount = await googlemodel.countDocuments({ status: "Success" });
        res.json({ count: successUserCount + successgoogleUserCount });
    } catch (error) {
        res.status(500).json({ error: 'Error counting users' });
    }
});
router.get('/buycourse',isUserSuccess,async(req,res)=>{
    console.log(req.user.role);
    
    res.json({ status: req.user.status });
})
router.post('/google', async (req, res) => {
 const { uid, name, email, profilePic, phone } = req.body;

  try {
    // Check if user already exists
    let user = await googlemodel.findOne({ uid });

    if (!user) {
      // If the user doesn't exist, create a new one
      user = new googlemodel({
        uid,
        name,
        email,
        profilePic,
        phone,
      });
      await user.save();
    } else {
      // Optionally, you can update the user if needed
      user.name = name;
      user.profilePic = profilePic;
      user.phone = phone;
      await user.save();
    }
    
        const accessToken = jwt.sign( { uid: user.uid, email: user.email },
            "EIBMgfsjkdkfbjkhfkhwhf",
            { expiresIn: '1h' })

 
        const refreshToken = jwt.sign( { uid: user.uid, email: user.email },
            "EIBMgfsjkdkfbjkhfkhwhf",
            { expiresIn: '1h' });
        

    // Set the token in a cookie
    res.cookie('accessToken', accessToken, {
        // httpOnly: true,  // Ensures the cookie is not accessible via JavaScript
        // secure: false,   // Set true if using HTTPS in production
        // maxAge: 3600000, // 1 hour (in milliseconds)
        // sameSite: 'strict', // Helps prevent CSRF attacks
      });
      res.cookie('refreshToken', refreshToken, {
        // httpOnly: true,  // Ensures the cookie is not accessible via JavaScript
        // secure: false,   // Set true if using HTTPS in production
        // maxAge: 3600000, // 1 hour (in milliseconds)
        // sameSite: 'strict', // Helps prevent CSRF attacks
      });
    res.status(200).json({ message: 'User authenticated successfully', user });
  } catch (error) {
    console.error("Error saving user to MongoDB:", error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
router.post('/admin/createBlog',isAdmin,upload.single('image'),async(req,res)=>{
    try {
        const {name,description,externalLink} = req.body
        const image = req.file.filename
        console.log(image);
        const blog = new BlogModel({
            name,
            description,
            image,
            externalLink,
        })
        await blog.save()
        res.status(200).json({message:'Blog created successfully',blog})
    } catch (error) {
        console.error("Error creating blog:", error);
        res.status(500).json({ message: 'Internal server error' });
        return false
    }
})
router.get('/getblog',async(req,res)=>{
    try {
        const blog = await BlogModel.find({})
        res.status(200).json({blog}) 
    } catch (error) {
        console.error("Error fetching blog:", error);
        res.status(500).json({ message: 'Internal server error' });
    }
})
router.post('/admin/deleteblog',isAdmin,async(req,res)=>{
    try {
        const {id} = req.body
        console.log(id);
        
        const blog = await BlogModel.findById(id);
        if (!blog) {
            return res.status(404).json({ message: 'Blog not found' });
        }

        // Construct the path to the image file
        const oldImagePath = path.join(__dirname, '..', 'uploads', blog.image);
       
       await fs.unlink(oldImagePath, (err) => {
            if (err) {
                console.error("Error deleting image:", err);
                return res.status(500).json({ message: 'Error deleting image' });
            }
        });
        try {
            console.log(id);
            
            // Delete the blog from the database
            await BlogModel.findByIdAndDelete(id);
            return res.status(200).json({ message: 'Blog and image deleted successfully' });
        } catch (err) {
            console.error("Error deleting blog:", err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        
    } catch (error) {
        console.error("Error deleting blog:", error);
        res.status(500).json({ message: 'Internal server error' });
    }
})
router.put('/admin/updateblog', upload.single('image'), async (req, res) => {
    const  id  = req.query.id;
    const { name, description, externalLink } = req.body;
  
    try {
      const blog = await BlogModel.findById(id);
  
      if (!blog) {
        return res.status(404).json({ message: "Blog not found" });
      }
  
      blog.name = name;
      blog.description = description;
      blog.externalLink = externalLink;
  
      if (req.file) {
        blog.image = req.file.filename;  // Update image if a new one is uploaded
      }
  
      await blog.save();
      res.json({ message: "Blog updated successfully", blog });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server error" });
    }
  });
router.get('/admin/getblog', async (req, res) => {
    const  id  = req.query.id;  // Extract blog ID from the route parameter
  
    try {
      // Find the blog by ID
      const blog = await BlogModel.findById(id);
  
      // If the blog is not found, return a 404 response
      if (!blog) {
        return res.status(404).json({ message: "Blog not found" });
      }
  
      // Return the blog data if found
      res.json({ blog });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server error" });
    }
  });
  router.post('/addcontact',async(req,res)=>{
    const { from_name, Phone_Number, Email, purpose, Address } = req.body;

    try {
      // Save form data to the database
      const newForm = new contactModel({
        name:from_name,
        phone:Phone_Number,
        email:Email,
        purpose:purpose,
        address:Address,
      });
  
      await newForm.save();
      return res.status(200).send({ message: "create" ,success:true});
    } catch (error) {
      console.log('Error:', error);
      res.status(500).json({ message: 'Failed to save form data!' });
    }
  })
  router.get('/showcontact',async(req,res)=>{
    try {
        const contact = await contactModel.find();
        return res.status(200).send({data:contact})
    } catch (error) {
        console.error(error);
      res.status(500).json({ message: "Server error" });
    }
  })
// Backend Route
router.post("/toggle-status", async (req, res) => {
    try {
      const { id, newStatus } = req.body; // Accept newStatus from the request
      console.log(req.body);
    
      const contact = await contactModel.findById(id);
      if (!contact) {
        return res.status(404).json({ message: "Contact not found" });
      }
      console.log("Before update:", contact);  // Log contact before update
      
      // Update the status to the selected newStatus
      contact.status = newStatus;
  
      // Explicitly mark the 'status' field as modified
      contact.markModified('status');
  
      const updatedContact = await contact.save();  // Save and wait for the promise to resolve
  
      console.log("After save:", updatedContact);  // Log the updated contact after save
      res.json(updatedContact);  // Return the updated contact
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server error" });
    }
  });
  router.post("/toggle-payment-status", async (req, res) => {
    try {
      const { id, newPaymentStatus } = req.body;
      
      const contact = await contactModel.findById(id);
      if (!contact) {
        return res.status(404).json({ message: "Contact not found" });
      }
  
      contact.paymentStatus = newPaymentStatus; // Update the payment status
      await contact.save();
      
      res.status(200).json(contact);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server error" });
    }
  });
  
  
  
  
module.exports = router