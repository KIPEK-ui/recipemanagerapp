const fs = require('fs');
const path = require('path');
const { insertRecipe, getAllRecipes, updateRecipe, deleteRecipe } = require('./db');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
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