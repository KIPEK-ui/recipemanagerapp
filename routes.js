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
const mongoose = require('mongoose');
const multer = require('multer');

// Define the schema for storing files in MongoDB
const fileSchema = new mongoose.Schema({
    name: String,
    data: Buffer,
    contentType: String,
});
const File = mongoose.model('File', fileSchema);

// Multer configuration
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Middleware to protect routes
async function auth(req, res, next) {
    const token = req.cookies.token;
    if (token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const user = await User.findById(decoded.user._id);
            if (!user) {
                return res.status(403).json({ msg: 'Token is not valid' });
            }
            req.user = user;
            next();
        } catch (err) {
            return res.status(403).json({ msg: 'Token is not valid' });
        }
    } else {
        res.status(401).json({ msg: 'Authorization cookie missing or invalid' });
    }
}

// JWT Strategy
const opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
};
passport.use(new JwtStrategy(opts, async(jwt_payload, done) => {
    try {
        const user = await User.findById(jwt_payload._id);
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
}, async(accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
            const randomPassword = crypto.randomBytes(16).toString('hex');
            user = new User({
                googleId: profile.id,
                email: profile.emails[0].value,
                password: randomPassword,
                firstName: profile.name.givenName,
                lastName: profile.name.familyName,
                googleAccessToken: accessToken,
                googleRefreshToken: refreshToken
            });
            await user.save();
        } else {
            user.googleAccessToken = accessToken;
            user.googleRefreshToken = refreshToken;
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
            const randomPassword = crypto.randomBytes(16).toString('hex');
            user = new User({
                githubId: profile.id,
                email: profile.emails[0].value,
                password: randomPassword,
                githubAccessToken: accessToken,
                githubRefreshToken: refreshToken
            });
            await user.save();
        } else {
            user.githubAccessToken = accessToken;
            user.githubRefreshToken = refreshToken;
            await user.save();
        }
        return done(null, user);
    } catch (err) {
        return done(err, false);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user._id);
});

passport.deserializeUser(async(id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, false);
    }
});

// Serve the favicon
router.get('/favicon.ico', (req, res) => {
    res.sendFile(path.join(__dirname, 'images', 'favicon.ico'));
});

// Serve the index page
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

// Serve the home page
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

// Google Authentication
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/auth/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
    const user = req.user;
    const payload = { user: { _id: user.id, firstName: user.firstName, lastName: user.lastName } };
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
        if (err) throw err;
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/home');
    });
});

// GitHub Authentication
router.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
router.get('/auth/github/callback', passport.authenticate('github', { session: false }), (req, res) => {
    const user = req.user;
    const payload = { user: { _id: user.id, firstName: user.firstName, lastName: user.lastName } };
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
        if (err) throw err;
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/home');
    });
});

// Authentication success route
// Authentication success route (INSECURE)
router.get('/auth/success', (req, res) => {
    const { token, userId, firstName, lastName } = req.query;
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
                    const userId = "${userId}";
                    const firstName = "${firstName}";
                    const lastName = "${lastName}";
                    if (token) {
                        localStorage.setItem('token', token);
                        localStorage.setItem('userId', userId);
                        localStorage.setItem('firstName', firstName);
                        localStorage.setItem('lastName', lastName);
                        alert('Authentication successful!');
                        window.location.href = '/home'; // Redirect to home page
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


// Logout route
router.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ msg: 'Logged out successfully' });
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

// Fetch logged-in user's information
router.get('/users/me', auth, async(req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }
        res.json(user);
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

// Retrieve all recipes with pagination
router.get('/recipes', async(req, res) => {
    const { page = 1, limit = 10 } = req.query;
    try {
        const recipes = await getAllRecipes(page, limit);
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

// Add a new recipe
router.post('/recipes', auth, upload.single('image'), async(req, res) => {
    const { name, ingredients, instructions, category, firstName, lastName } = req.body;
    const userId = req.user.id;
    const recipe = { name, ingredients, instructions, category, firstName, lastName, user: userId };

    if (req.file) {
        const imageFile = req.file;
        const newFile = new File({
            name: imageFile.originalname,
            data: imageFile.buffer,
            contentType: imageFile.mimetype,
        });
        try {
            const savedFile = await newFile.save();
            recipe.image = savedFile._id.toString(); // Convert ObjectId to string
        } catch (err) {
            console.error('Error saving file:', err);
            return res.status(500).json({ message: 'Error saving file' });
        }
    } else {
        return res.status(400).json({ message: 'Image is required' });
    }

    try {
        await insertRecipe(recipe, userId);
        res.status(200).json({ message: 'Recipe inserted successfully' });
    } catch (err) {
        console.error('Error inserting recipe:', err);
        res.status(500).json({ message: 'Error inserting recipe' });
    }
});

// Update a recipe
router.patch('/recipes/:id', auth, upload.single('image'), async(req, res) => {
    const { id } = req.params;
    const { name, ingredients, instructions, category } = req.body;
    const userId = req.user.id;
    const recipe = { name, ingredients, instructions, category, user: userId };

    if (req.file) {
        const imageFile = req.file;
        const newFile = new File({
            name: imageFile.originalname,
            data: imageFile.buffer,
            contentType: imageFile.mimetype,
        });
        try {
            const savedFile = await newFile.save();
            recipe.image = savedFile._id.toString(); // Convert ObjectId to string
        } catch (err) {
            console.error('Error saving file:', err);
            return res.status(500).json({ message: 'Error saving file' });
        }
    }

    try {
        const updatedRecipe = await updateRecipe(id, recipe, userId);
        if (!updatedRecipe) {
            return res.status(404).json({ message: 'Recipe not found' });
        }
        res.status(200).json({ message: 'Recipe updated successfully', updatedRecipe });
    } catch (err) {
        console.error('Error updating recipe:', err);
        res.status(500).json({ message: 'Error updating recipe' });
    }
});

// Delete a recipe
router.delete('/recipes/:id', auth, async(req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    try {
        const result = await deleteRecipe(id, userId);
        if (!result) {
            return res.status(404).json({ message: 'Recipe not found' });
        }
        res.status(200).json({ message: 'Recipe deleted successfully', result });
    } catch (err) {
        console.error('Error deleting recipe:', err);
        res.status(500).json({ message: 'Error deleting recipe' });
    }
});
module.exports = router;