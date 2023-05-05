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

// Homepage
app.get('/', (req, res) => {
    const fakeRouteNumber = Math.floor(Math.random() * 10) + 1;
    if (!req.session.AUTH) {
        res.render('homeRouteUnauthorized.ejs', {});
    } else {
        res.render('homeRouteAuthorized.ejs', {
            "user": req.session.USERNAME,
            'isAdmin': (req.session.USER.role === 'Admin')
        })
    }
});

// Sign Up Page
app.get('/signup', (req, res) => {
    res.render('signupRoute.ejs')
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


// Invalid form data page
app.get('/invalidFormData', (req, res) => {
    res.render('invalidFormDataRoute.ejs', {
        'invalidField': req.session.INVALID_FIELD,
        'referer': req.headers.referer
    })
})


// Log In Page
app.get('/login', (req, res) => {
    res.render('loginRoute');
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


// Checks if the user is authenticated.
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


// On failed authentication
app.get('/authFail', (req, res) => {
    res.render('authFailRoute', {
        'referer': req.headers.referer
    })
})


// Auth route only allowed for authenticated users
app.get('/members', checkAuth, (req, res) => {
    const imageNumber = Math.floor(Math.random() * 3) + 1;
    res.render('membersRoute', {
        'imageNum': imageNumber,
        'username': req.session.USERNAME
    })
});


// Log out destroys session
app.get('/logOut', (req, res) => {
    req.session.destroy();
    res.redirect('./');
})


// Checks if the user is an admin
const checkAdmin = (req, res, next) => {
    if (!(req.session.USER.role === 'Admin')) {
        return res.redirect('/notAnAdmin');
    }
    next();
}


// Admin route to change role
app.get('/admin', checkAuth, checkAdmin, async (req, res) => {
    const users = await User.find();
    const user = await User.findOne({ name: req.session.USERNAME })

    res.render('adminRoute', {
        'primaryUser': user,
        'users': users
    })
})


// Not an admin route
app.get('/notAnAdmin', (req, res) => {
    res.render('notAnAdminRoute')
})


// Handle the admin to user role change
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

// Handle the user tp admin role change
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

// 404 Page
app.get('/does_not_exist', (req, res) => {
    res.status(404);
    res.render('doesNotExistRoute');
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