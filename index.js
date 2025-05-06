require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hours 

/* This is my env stuff*/
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});
//connect to mongooooo
app.use(session({ 
    secret: node_session_secret,
    store: mongoStore, 
    saveUninitialized: false, 
    resave: true,
    cookie: {
        httpOnly: true, 
        secure: process.env.NODE_ENV === 'production', 
        maxAge: expireTime
    }
}));


function isAuthenticated(req) {
    return req.session.authenticated;
}

function authenticateUser(req, res, next) {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }
    
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    next();
}

// Home page
app.get('/', (req, res) => {
    let html = `<h1>Welcome to the Website</h1>`;
    
    if (isAuthenticated(req)) {
        html += `
            <p>Hello, ${req.session.name}</p>
            <a href="/members">Go to Members Area</a><br>
            <a href="/logout">Log out</a>
        `;
    } else {
        html += `
            <a href="/signup">Sign up</a><br>
            <a href="/login">Log in</a>
        `;
    }
    
    res.send(html);
});

// Sign up page
app.get('/signup', (req, res) => {
    let missingFields = req.query.missing;
    let html = `
        <h1>Sign Up</h1>
        <form action='/submitSignup' method='post'>
            <input name='name' type='text' placeholder='Name'><br>
            <input name='email' type='text' placeholder='Email'><br>
            <input name='password' type='password' placeholder='Password'><br>
            <button>Submit</button>
        </form>
    `;
    
    if (missingFields) {
        html += `<p style="color: red">Please provide ${missingFields}</p>`;
    }
    
    res.send(html);
});

// Submit sign up
app.post('/submitSignup', async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;
    
    // Check for missing fields
    const missingFields = [];
    if (!name) missingFields.push('a name');
    if (!email) missingFields.push('an email address');
    if (!password) missingFields.push('a password');
    
    if (missingFields.length > 0) {
        const missing = missingFields.join(' and ');
        res.redirect(`/signup?missing=${missing}`);
        return;
    }
    
    // Joi validation you could also use yup 
    const schema = Joi.object({
        name: Joi.string().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });
    
    const validationResult = schema.validate({ name, email, password });
    
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/signup");
        return;
    }
    
    // Check if the email is already in use
    const existingUser = await userCollection.findOne({ email: email });
    
    if (existingUser) {
        res.send(`
            <p>Email already in use. Please use a different email.</p>
            <a href="/signup">Try again</a>
        `);
        return;
    }
    
    // Hash password and create user
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword
    });
    
    // Create session and redirect
    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;
    
    res.redirect('/members');
});

// Login page
app.get('/login', (req, res) => {
    let loginFailed = req.query.failed;
    let html = `
        <h1>Log In</h1>
        <form action='/loggingin' method='post'>
            <input name='email' type='text' placeholder='Email'><br>
            <input name='password' type='password' placeholder='Password'><br>
            <button>Submit</button>
        </form>
    `;
    
    if (loginFailed) {
        html += `<p style="color: red">User and password not found.</p>`;
    }
    
    res.send(html);
});

// Submit login
app.post('/loggingin', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    
    // Joi validation
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });
    
    const validationResult = schema.validate({ email, password });
    
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login?failed=true");
        return;
    }
    
    const result = await userCollection.find({ email: email }).toArray();
    
    if (result.length != 1) {
        console.log("User not found");
        res.redirect("/login?failed=true");
        return;
    }
    
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("Correct password");
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.email = email;
        req.session.cookie.maxAge = expireTime;
        
        res.redirect('/members');
        return;
    } else {
        console.log("Incorrect password");
        res.redirect("/login?failed=true");
        return;
    }
});

app.get('/members', authenticateUser, (req, res) => {
    
    // Choose a  image 
    const images = ['image1.gif','socks.gif', 'naruto.png'];
    const randomImage = images[Math.floor(Math.random() * images.length)];
    
    let html = `
        <h1>Members Area</h1>
        <p>Hello, ${req.session.name}</p>
        <img src="/${randomImage}" style="width: 250px;"><br>
        <a href="/logout">Log out</a>
    `;
    
    res.send(html);
});
//delete session
app.get('/logout', (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    // Destroy the session 
    req.session.destroy((err) => {
        if (err) {
            console.log("Error destroying session:", err);
        }
        
        // Clear the session cookie
        res.clearCookie('connect.sid'); //cookie
        
        // Redirect to home page
        res.redirect('/');
    });
});

// Serve static files
app.use(express.static(__dirname + "/public"));

// 404 page
app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});