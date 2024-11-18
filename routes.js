const fs = require('fs');
const path = require('path');
const { insertRecipe, getAllRecipes, getRecipeById, getRecipesByCategory, getRecipesByUser, updateRecipe, deleteRecipe } = require('./db');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const router = express.Router();

router.get('/', (req, res) => {
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
router.get('/home', (req, res) => {
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
// User registration
router.post('/register', [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password must be 6 or more characters').isLength({ min: 6 })
], async(req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        user = new User({ email, password });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        await user.save();

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

// User login
router.post('/login', [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
], async(req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

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

// Middleware to protect routes
const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

// Secure endpoint example
router.get('/users', auth, async(req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
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

// List of all recipes (insecure endpoint)
router.get('/recipes', async(req, res) => {
    try {
        const recipes = await getAllRecipes();
        res.json(recipes);
    } catch (err) {
        console.error('Error fetching recipes:', err);
        res.status(500).json({ message: 'Error fetching recipes' });
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