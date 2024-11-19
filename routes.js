const fs = require('fs');
const path = require('path');
const { User, insertUser, insertRecipe, getAllRecipes, getRecipeById, getRecipesByCategory, getRecipesByUser, updateRecipe, deleteRecipe } = require('./db');
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github').Strategy;
const router = express.Router();
const multer = require('multer');
const mongoose = require('mongoose');

// Define the schema for storing files in MongoDB
const fileSchema = new mongoose.Schema({
    name: String,
    data: Buffer,
    contentType: String,
});

const File = mongoose.model('File', fileSchema);

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Middleware to protect routes
function auth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        console.log('Received token:', token); // Log the token for debugging
        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                console.error('Token verification error:', err); // Log the error
                return res.status(403).json({ msg: 'Token is not valid' });
            }
            req.user = user;
            next();
        });
    } else {
        res.status(401).json({ msg: 'Authorization header missing or invalid' });
    }
}


// Use the auth middleware for protected routes
router.get('/api/recipes', auth, async(req, res) => {
    try {
        const recipes = await getAllRecipes();
        res.status(200).json(recipes);
    } catch (err) {
        console.error('Error fetching recipes:', err);
        res.status(500).json({ message: 'Error fetching recipes' });
    }
});


// Serve the favicon
router.get('/favicon.ico', (req, res) => {
    res.sendFile(path.join(__dirname, 'images', 'favicon.ico'));
});

router.get('/', (req, res) => {
    fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
        if (err) {
            res.writeHead(500, { 'Content-Type': 'text/html' });
            res.end("Error loading form");
        } else {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        }
    });
});

router.get('/home', auth, (req, res) => {
    fs.readFile(path.join(__dirname, 'recipes.html'), (err, data) => {
        if (err) {
            res.writeHead(500, { 'Content-Type': 'text/html' });
            res.end("Error loading Page");
        } else {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        }
    });
});

// JWT Strategy
const opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
};

passport.use(new JwtStrategy(opts, async(jwt_payload, done) => {
    try {
        const user = await User.findById(jwt_payload.id);
        if (user) {
            return done(null, user);
        } else {
            return done(null, false);
        }
    } catch (err) {
        return done(err, false);
    }
}));

// Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
}, async(token, tokenSecret, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
            const randomPassword = crypto.randomBytes(16).toString('hex');
            user = new User({
                googleId: profile.id,
                email: profile.emails[0].value,
                password: randomPassword
            });
            await user.save();
        }
        return done(null, user);
    } catch (err) {
        return done(err, false);
    }
}));

// GitHub Strategy
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: '/auth/github/callback'
}, async(accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ githubId: profile.id });
        if (!user) {
            user = new User({ githubId: profile.id, email: profile.emails[0].value });
            await user.save();
        }
        return done(null, user);
    } catch (err) {
        return done(err, false);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async(id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, false);
    }
});

// List of all recipes (insecure endpoint)
router.post('/recipes', upload.single('image'), async(req, res) => {
    const { name, ingredients, instructions } = req.body;
    const file = req.file;

    const recipe = { name, ingredients, instructions };

    if (file) {
        const newFile = new File({
            name: file.originalname,
            data: file.buffer,
            contentType: file.mimetype,
        });

        try {
            await newFile.save();
            recipe.image = newFile._id;
        } catch (err) {
            console.error('Error saving file:', err);
            return res.status(500).json({ message: 'Error saving file' });
        }
    }

    try {
        await insertRecipe(recipe);
        res.status(200).json({ message: 'Recipe inserted successfully' });
    } catch (err) {
        console.error('Error inserting recipe:', err);
        res.status(500).json({ message: 'Error inserting recipe' });
    }
});


// Retrieve all recipes
router.get('/recipes', async(req, res) => {
    try {
        const recipes = await getAllRecipes();
        res.status(200).json(recipes);
    } catch (err) {
        console.error('Error fetching recipes:', err);
        res.status(500).json({ message: 'Error fetching recipes' });
    }
});

// Retrieve an image by ID
router.get('/images/:id', async(req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ message: 'Invalid ObjectId' });
    }

    try {
        const file = await File.findById(id);
        if (!file) {
            return res.status(404).json({ message: 'File not found' });
        }
        res.set('Content-Type', file.contentType);
        res.send(file.data);
    } catch (err) {
        console.error('Error fetching file:', err);
        res.status(500).json({ message: 'Error fetching file' });
    }
});

// Update a recipe
router.post('/recipes/:id', upload.single('image'), async(req, res) => {
    const { id } = req.params;
    const { name, ingredients, instructions } = req.body;
    const file = req.file;

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ message: 'Invalid ObjectId' });
    }

    const recipe = { name, ingredients, instructions };

    if (file) {
        const newFile = new File({
            name: file.originalname,
            data: file.buffer,
            contentType: file.mimetype,
        });

        try {
            await newFile.save();
            recipe.image = newFile._id;
        } catch (err) {
            console.error('Error saving file:', err);
            return res.status(500).json({ message: 'Error saving file' });
        }
    }

    try {
        await updateRecipe(id, recipe);
        res.status(200).json({ message: 'Recipe updated successfully' });
    } catch (err) {
        console.error('Error updating recipe:', err);
        res.status(500).json({ message: 'Error updating recipe' });
    }
});

// Delete a recipe
router.delete('/recipes/:id', async(req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ message: 'Invalid ObjectId' });
    }

    try {
        const result = await deleteRecipe(id);
        if (result) {
            res.status(200).json({ message: 'Recipe deleted successfully', result });
        } else {
            res.status(404).json({ message: 'Recipe not found' });
        }
    } catch (err) {
        console.error('Error deleting recipe:', err);
        res.status(500).json({ message: 'Error deleting recipe' });
    }
});

// User registration
// Register
router.post('/register', async(req, res) => {
    const { email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        user = await insertUser(email, password);

        const payload = { user: { id: user.id } };

        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Login
router.post('/login', async(req, res) => {
    const { email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        const payload = { user: { id: user.id } };

        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Google Authentication
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/auth/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
    const payload = { user: { id: req.user.id } };
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
        if (err) throw err;
        res.redirect(`/auth/success?token=${token}`);
    });
});

// GitHub Authentication
router.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

router.get('/auth/github/callback', passport.authenticate('github', { session: false }), (req, res) => {
    const payload = { user: { id: req.user.id } };
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
        if (err) throw err;
        res.redirect(`/auth/success?token=${token}`);
    });
});

// Authentication success route
router.get('/auth/success', (req, res) => {
    const token = req.query.token;
    const htmlContent = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Authentication Success</title>
        </head>
        <body>
            <script>
                (function() {
                    const token = "${token}";
                    if (token) {
                        localStorage.setItem('token', token);
                        alert('Authentication successful!');
                        window.location.href = '/'; // Redirect to home page
                    } else {
                        alert('Authentication failed!');
                        window.location.href = '/'; // Redirect to login page
                    }
                })();
            </script>
        </body>
        </html>
    `;
    res.send(htmlContent);
});

// List of all users
router.get('/users', auth, async(req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// One user’s details by email/id
router.get('/users/:id', auth, async(req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// List of all users by gender (assuming gender field exists)
router.get('/users/gender/:gender', auth, async(req, res) => {
    try {
        const users = await User.find({ gender: req.params.gender });
        res.json(users);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});


// Recipe information by id
router.get('/recipes/:id', async(req, res) => {
    try {
        const recipe = await getRecipeById(req.params.id);
        if (!recipe) {
            return res.status(404).json({ message: 'Recipe not found' });
        }
        res.json(recipe);
    } catch (err) {
        console.error('Error fetching recipe:', err);
        res.status(500).json({ message: 'Error fetching recipe' });
    }
});

// List of all recipes by category/subcategory
router.get('/recipes/category/:category', async(req, res) => {
    try {
        const recipes = await getRecipesByCategory(req.params.category);
        res.json(recipes);
    } catch (err) {
        console.error('Error fetching recipes:', err);
        res.status(500).json({ message: 'Error fetching recipes' });
    }
});

// List of recipes by a user (secure endpoint)
router.get('/recipes/user/:userId', auth, async(req, res) => {
    try {
        const recipes = await getRecipesByUser(req.params.userId);
        res.json(recipes);
    } catch (err) {
        console.error('Error fetching recipes:', err);
        res.status(500).json({ message: 'Error fetching recipes' });
    }
});

module.exports = router;