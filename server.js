const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const Joi = require('joi');
const bcrypt = require('bcrypt');
const saltRounds = 10

require('dotenv').config();

const app = express();
const Schema = mongoose.Schema;

app.use(express.urlencoded({ extended: false }))
app.use(express.json());
app.use(express.static(`public`));

const uri = process.env.ATLAS_URI;
mongoose.connect(uri, { useNewUrlParser: true });
mongoose.connection.useDb('Assignment1')
mongoose.connection.once('open', () => {
    console.log("Connected to MongoDB Atlas.")
})

var sessionStore = MongoStore.create({
    mongoUrl: uri,
    cypto: {
        secret: process.env.SESSION_KEY
    }
})

app.use(session({
    secret: process.env.SESSION_KEY,
    store: sessionStore,
    saveUninitialized: false,
    resave: true,
    cookie: { maxAge: 60 * 60 * 1000 }
}))

// The '$ : {} ()' characters is used to get information from mongoDB, so it is not allowed. e.g. username: {$exists: true}}
const nameSchema = Joi.string().regex(/^[a-zA-Z]+$/).required();
const emailSchema = Joi.string().email({ minDomainSegments: 2 }).regex(/^[a-zA-Z0-9!@#%^&*_+=[\]\\|;'",.<>/?~`-]+$/).required();
const passwordSchema = Joi.string().regex(/^[a-zA-Z0-9!@#%^&*_+=[\]\\|;'",.<>/?~`-]+$/).required();

// Homepage
app.get('/', (req, res) => {
    const fakeRouteNumber = Math.floor(Math.random() * 10) + 1;
    if (!req.session.AUTH) {
        res.send(`
        <form style="margin-bottom:2px" action="./signup">
        <input type="submit" value="Sign Up" />
        </form>
        <form style="margin-bottom:2px" action="./login">
            <input type="submit" value="Log In" />
        </form>
        <form style="margin-bottom:2px" action="./fakeRoute${fakeRouteNumber}">
            <input type="submit" value="Unknown Page" />
        </form>
`)
    } else {
        res.send(`
    <h3 style="margin-bottom:2px"> Hello, ${req.session.USERNAME}!</h3>
        <form style="margin-bottom:2px" action="./members">
        <input type="submit" value="Members Area" />
        </form>
    <form style="margin-bottom:2px" action="./logOut" method="getS">
        <input type="submit" value="Log Out" />
    </form>
    `)
    }

});


// User Model
const userSchema = new Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Sign Up Page
app.get('/signup', (req, res) => {
    res.send(`
    <h3 style="margin-bottom:2px">Sign Up</h3 >
        <form style="margin-bottom:2px" action="/signup" method="post">
        <input type="text" id="name" name="name" placeholder="name"><br>
        <input type="text" id="email" name="email" placeholder="email"><br>
        <input style="margin-bottom:2px" type="password" id="password" name="password" placeholder="password"><br>
                    <input type="submit" id="submit" value="Sign Up">
                    </form>
        <form style="margin-bottom:2px" action="./">
        <input type="submit" value="Home" />
        </form>
                    `)
});


// // Write form data to database
app.post('/signup', async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    let password = req.body.password;

    const nameValidationResult = nameSchema.validate(name);
    const emailValidationResult = emailSchema.validate(email);
    const passwordValidationResult = passwordSchema.validate(password);

    if (nameValidationResult.error != null) {
        req.session.INVALID_FIELD = 'Name'
        res.redirect('/invalidFormData')
    } else if (emailValidationResult.error != null) {
        req.session.INVALID_FIELD = 'Email'
        res.redirect('/invalidFormData')
    } else if (passwordValidationResult.error != null) {
        req.session.INVALID_FIELD = 'Password'
        res.redirect('/invalidFormData')
    } else {
        password = await bcrypt.hash(req.body.password, saltRounds);
        console.log(password)
        const newUser = new User({
            name,
            email,
            password
        })
        newUser.save().then(() => {
            req.session.AUTH = true;
            req.session.USERNAME = req.body.name;
            res.redirect('/members')
        })
    }
});


// Invalid form data page
app.get('/invalidFormData', (req, res) => {
    res.send(`
    ${req.session.INVALID_FIELD} is invalid. <br><br>
    <a href="${req.headers.referer}">Try again</a>.
    `)
})


// Log In Page
app.get('/login', (req, res) => {
    res.send(`
    <h3 style="margin-bottom:2px">Log In</h3>
<form style="margin-bottom:2px" action="/login" method="post">
    <input type="text" id="email" name="email" placeholder="email"><br>
    <input style="margin-bottom:2px" type="password" id="password" name="password" placeholder="password"><br>
    <input type="submit" id="submit" value="Log In">
</form>
        <form style="margin-bottom:2px" action="./">
        <input type="submit" value="Home" />
        </form>
`)
})


// Find Matching User login
app.post(('/login'), (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    const emailValidationResult = emailSchema.validate(email);
    const passwordValidationResult = passwordSchema.validate(password);

    User.find(({ email: email })).exec().then(async (users) => {

        if (emailValidationResult.error != null) {
            req.session.INVALID_FIELD = 'Email'
            res.redirect('/invalidFormData')
        } else if (passwordValidationResult.error != null) {
            req.session.INVALID_FIELD = 'Password'
            res.redirect('/invalidFormData')
        } else {
            if (users.length === 0) {
                console.log("Unauth")
                req.session.AUTH = false;
                req.session.failForm = true;
            } else {
                if (await bcrypt.compare(password, users[0].password)) {
                    console.log("Auth")
                    req.session.AUTH = true;
                    req.session.USERNAME = users[0].name;
                } else {
                    console.log("Unauth")
                    req.session.AUTH = false;
                    req.session.failForm = true;
                }
            }
            res.redirect('/members');
        }
    })
});


// Checks if the user is authenticated.
const checkAuth = (req, res, next) => {
    if (!req.session.AUTH) {
        if (req.session.failForm) {
            delete req.session.failForm
            return res.redirect('/authFail');
        } else {
            delete req.session.failForm
            return res.redirect('/');
        }
    }
    next();
};


// On failed authentication
app.get('/authFail', (req, res) => {
    res.send(`No match found <br>
     <a href="${req.headers.referer}">Try again</a>.   
    `)
})


// Auth route only allowed for authenticated users
app.get('/members', checkAuth, (req, res) => {
    const imageNumber = Math.floor(Math.random() * 3) + 1;
    res.send(`
    <h3 style="margin-bottom:2px"> Hello, ${req.session.USERNAME}!</h3>
    <img style="margin-bottom:2px" src="/images/a1img${imageNumber}.png">
        
    <form style="margin-bottom:2px" margin-bottom:2px action="./">
        <input type="submit" value="Home" />
    </form>
    <form style="margin-bottom:2px" margin-bottom:2px action="./logOut" method="get">
        <input type="submit" value="Log Out" />
    </form>
    `)
});


// Log out destroys session
app.get('/logOut', (req, res) => {
    req.session.destroy();
    res.redirect('./');
})


// 404 Page
app.get('/does_not_exist', (req, res) => {
    console.log("Not found")
    res.status(404);
    res.send(`
    Error 404 - that page does not exist.<br>
    <a href="/">Home</a>
    `);
})


// Page not found
app.get('*', (req, res) => {
    res.redirect('/does_not_exist')
})


// Start server
const port = 8080;
app.listen((port), () => {
    console.log(`Server is running on port ${port}; http://localhost:${port}`);
});