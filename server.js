const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const Joi = require('joi');
const bcrypt = require('bcrypt');
const saltRounds = 10
const ejs = require('ejs');

require('dotenv').config();

const app = express();
const Schema = mongoose.Schema;

app.use(express.urlencoded({ extended: false }))
app.use(express.json());
app.use(express.static(`public`));
app.set('view engine', 'ejs');

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

// User Model
const userSchema = new Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Get Home page
app.get('/', (req, res) => {
    res.render('homeRoute', { primaryUser: req.session.USER });
});


// Get signup page
app.get('/signup', (req, res) => {
    res.render('signupRoute.ejs', { primaryUser: req.session.USER })
});


// Post signup page
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
        const newUser = new User({
            name,
            email,
            password,
            role: 'User'
        })
        newUser.save().then(async () => {
            req.session.USER = await User.findOne({ name: req.body.name })
            req.session.AUTH = true;
            req.session.USERNAME = req.body.name;
            req.session.ROLE = 'User'
            res.redirect('/members')
        })
    }
});


// Get invalid form data page
app.get('/invalidFormData', (req, res) => {
    res.render('invalidFormDataRoute.ejs', {
        primaryUser: req.session.USER,
        invalidField: req.session.INVALID_FIELD,
        referer: req.headers.referer
    })
})


// Get login page
app.get('/login', (req, res) => {
    res.render('loginRoute', { primaryUser: req.session.USER });
})


// Post login page
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
                req.session.AUTH = false;
                req.session.FAIL_FORM = true;
            } else {
                if (await bcrypt.compare(password, users[0].password)) {
                    req.session.AUTH = true;
                    req.session.USERNAME = users[0].name;
                    req.session.ROLE = users[0].role;
                    req.session.USER = users[0]
                } else {
                    req.session.AUTH = false;
                    req.session.FAIL_FORM = true;
                }
            }
            res.redirect('/members');
        }
    })
});


// Middleware: Checks if the user is authenticated
const checkAuth = (req, res, next) => {
    if (!req.session.AUTH) {
        if (req.session.FAIL_FORM) {
            delete req.session.FAIL_FORM
            return res.redirect('/authFail');
        } else {
            delete req.session.FAIL_FORM
            return res.redirect('/login');
        }
    }
    next();
};


// Get authentication failure page
app.get('/authFail', (req, res) => {
    res.render('authFailRoute', {
        primaryUser: req.session.USER,
        referer: req.headers.referer
    })
})


// Get members page
app.get('/members', checkAuth, (req, res) => {
    const imageNumber = Math.floor(Math.random() * 3) + 1;
    res.render('membersRoute', {
        primaryUser: req.session.USER,
        imageNum: imageNumber,
    })
});


// Post logout page
app.post('/logOut', (req, res) => {
    req.session.destroy();
    res.redirect('./');
})


// Middleware: Checks if the user is an admin
const checkAdmin = (req, res, next) => {
    if (!(req.session.USER.role === 'Admin')) {
        return res.redirect('/notAnAdmin');
    }
    next();
}


// Get admin page
app.get('/admin', checkAuth, checkAdmin, async (req, res) => {
    const users = await User.find();

    res.render('adminRoute', {
        primaryUser: req.session.USER,
        users: users
    })
})


// Get not an page
app.get('/notAnAdmin', (req, res) => {
    res.render('notAnAdminRoute', { primaryUser: req.session.USER })
})


// Post promotion of selected user
app.post('/promote/:id', async (req, res) => {
    const username = req.params.id;
    User.updateOne(
        { name: username },
        { $set: { role: 'Admin' } }
    ).then(async (result) => {
        const updatedUser = await User.findOne({ name: username })
        if (updatedUser.name === req.session.USER.name) {
            req.session.USER = updatedUser;
        }
        res.redirect('/admin')
    })
})

// Post demotion of selected user
app.post('/demote/:id', async (req, res) => {
    const username = req.params.id;
    User.updateOne(
        { name: username },
        { $set: { role: 'User' } }
    ).then(async (result) => {
        const updatedUser = await User.findOne({ name: username })
        if (updatedUser.name === req.session.USER.name) {
            req.session.USER = updatedUser;
        }
        res.redirect('/admin')
    })
})

// Get 404 Page
app.get('/does_not_exist', (req, res) => {
    res.status(404);
    res.render('doesNotExistRoute', { primaryUser: req.session.USER });
})


// Get Page not found page
app.get('*', (req, res) => {
    res.redirect('/does_not_exist')
})


// Start server
const port = 8080;
app.listen((port), () => {
    console.log(`Server is running on port ${port}; http://localhost:${port}`);
});