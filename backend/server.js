const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const router = require('./routes/router');
const cookieParser = require('cookie-parser');
// const passport = require('./config/passport');
const ConnectDb = require('./config/db');
// const session = require('express-session');
const path = require('path')
const cookieSession = require('cookie-session')
const port = process.env.PORT || 3000
dotenv.config();

const app = express();
app.use(cookieSession({
    name : "sessiom",
    keys : ["cyberwolve"],
    maxAge : 24*60*60*100
 }));
 
//  app.use(passport.initialize());
//  app.use(passport.session());
const corsOptions = {
    origin: 'https://eibm.in',  // Update with your client URL
    credentials: true, // This allows cookies to be sen 
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));



ConnectDb();

app.use('/auth', router);

app.listen(port, (err) => {
    if (err) console.log(err);
    console.log(`Server Running On The Port = ${port}`);
});
