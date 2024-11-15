const fs = require('fs');
const path = require('path');
const { connectToDatabase, insertRecipe, getAllRecipes, updateRecipe, deleteRecipe } = require('./db');
const multer = require('multer');
const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();

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

router.get('/recipes', async(req, res) => {
    try {
        const recipes = await getAllRecipes();
        res.status(200).json(recipes);
    } catch (err) {
        console.error('Error fetching recipes:', err);
        res.status(500).json({ message: 'Error fetching recipes' });
    }
});

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

module.exports = router;