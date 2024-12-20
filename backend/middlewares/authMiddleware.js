const jwt = require('jsonwebtoken'); // Assuming JWT is used for token-based authentication
const AdmissionForm = require('../models/admission');
const UserModel = require('../models/user');
const googleuser = require('../models/googleuser');
const checkAuthenticated = (req, res, next) => {
    try {
        
        
        
        // Get the token from cookies (or headers if that's how you manage tokens)
        const token = req?.cookies?.accessToken
        // console.log(token);
        
        if (!token) {
            return res.status(401).json({ message: "Access denied. Please log in first." });
        }

        // Verify the token
        jwt.verify(token,"EIBMgfsjkdkfbjkhfkhwhf", (err, user) => { // Replace `process.env.JWT_SECRET` with your secret key
            if (err) {
                return res.status(403).json({ message: "Invalid or expired token. Please log in again." });
            }
            
            
            // Attach user info to the request (optional)
            req.user = user;

            // Proceed to the next middleware or route handler
            next();
        });
    } catch (error) {
        res.status(500).json({
            message: error.message
        });
        console.log(error);
        
    }
};
const checkAdmissionExists = async (req, res, next) => {
    try {
        const token = req.cookies.accessToken;

        if (!token) {
            return res.status(401).json({ message: "Unauthorized. Please log in." });
        }
        
        const decoded = jwt.verify(token,"EIBMgfsjkdkfbjkhfkhwhf"); // Replace with your actual secret key
        const userId = decoded.id;

        // Check if the admission form already exists for this user
        const admissionForm = await AdmissionForm.findOne({ userId });

        if (admissionForm) {
            return res.status(403).json({ 
                message: "You have already submitted the admission form. No need to submit again." 
            });
        }

        // Proceed to the next middleware or route handler if no admission form is found
        next();
    } catch (error) {
        res.status(500).json({
            message: error.message
        });
    }
};
const ISAdmission = async(req,res) => {
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
    } catch (error) {
        
    }
}
const authenticateUser = async (req, res, next) => {
    const token = req.cookies.token // Extract token from Authorization header

    if (!token) {
        return res.status(401).json({ message: "No token provided, authorization denied" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JET_SECRET);
        req.user = await UserModel.findById(decoded.id).select('-password'); // Fetch user details without password

        if (!req.user) {
            return res.status(404).json({ message: "User not found" });
        }

        next();
    } catch (error) {
        console.error("Authentication error:", error);
        return res.status(401).json({ message: "Token is not valid" });
    }
};
const isAdmin = async(req, res, next) => {
    try {
        // Extract token from cookies
        const token = req.cookies.accessToken;
        
        if (!token) {
            return res.status(403).json({ message: 'Unauthorized' });
        }

        // Verify token
        const decoded = jwt.verify(token, "EIBMgfsjkdkfbjkhfkhwhf");
        req.user = decoded;
        const user = await UserModel.findById(req.user.id)
        if(!user){
            let googleuser = await googleuser.findOne({uid : req.user.id})
            if (googleuser.role != 'admin') {
                return res.status(403).json({ message: 'Access denied. You are not authorized to access this resource.' });
            }
            if(googleuser.role=='admin'){
                console.log("done");
                
            }
            req.user = googleuser
            // If the user is an admin, proceed to the next middleware or route handler
            next();
        }
        
        
        
       
        // Check if user is an admin
        if (user.role != 'admin') {
            return res.status(403).json({ message: 'Access denied. You are not authorized to access this resource.' });
        }
        if(user.role=='admin'){
            console.log("done");
            
        }
        req.user = user
        // If the user is an admin, proceed to the next middleware or route handler
        next();
    } catch (error) {
        console.error('Authorization error:', error);
        return res.status(403).json({ message: 'Unauthorized' });
    }
};
const isUserSuccess = async (req, res, next) => {
    try {
        // Extract token from cookies
        const token = req.cookies.accessToken;
        
        if (!token) {
            return res.status(403).json({ message: 'Unauthorized' });
        }

        // Verify token
        const decoded = jwt.verify(token, "EIBMgfsjkdkfbjkhfkhwhf"); // Ensure JWT_SECRET is correct
        req.user = decoded;

        // Fetch user details from the database
        const user = await UserModel.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check if user's status is "Success"
        if (user.status !== 'Success') {
            return res.status(403).json({ message: 'Access denied. User status is not "Success".' });
        }

        // If the user's status is "Success", proceed to the next middleware or route handler
        req.user = user; // Update req.user with the full user details
        next();
    } catch (error) {
        console.error('Authorization error:', error);
        return res.status(403).json({ message: 'Unauthorized' });
    }
};

module.exports = isUserSuccess;

module.exports ={ checkAuthenticated,checkAdmissionExists,isAdmin,isUserSuccess};

