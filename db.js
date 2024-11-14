const mongoose = require('mongoose');

const MONGOURL = process.env.MONGO_URL;
// Connect to MongoDB
mongoose.connect(MONGOURL, {}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('Error connecting to MongoDB:', err);
});

// Define the Recipe schema
const recipeSchema = new mongoose.Schema({
    name: { type: String, required: true },
    ingredients: { type: String, required: true },
    instructions: { type: String, required: true },
    image: { type: String, required: true }
});

// Create the Recipe model
const Recipe = mongoose.model('Recipe', recipeSchema);

// Insert a new recipe into the database
async function insertRecipe(recipe) {
    try {
        const newRecipe = new Recipe(recipe);
        const result = await newRecipe.save();
        console.log('Recipe inserted successfully:', result);
        return result;
    } catch (err) {
        console.error('Error inserting recipe:', err);
        throw err;
    }
}

// Retrieve all recipes from the database
async function getAllRecipes() {
    try {
        const recipes = await Recipe.find();
        console.log('Recipes fetched successfully:', recipes);
        return recipes;
    } catch (err) {
        console.error('Error fetching recipes:', err);
        throw err;
    }
}

// Update a recipe in the database
async function updateRecipe(id, recipe) {
    try {
        const result = await Recipe.findByIdAndUpdate(id, recipe, { new: true });
        console.log('Recipe updated successfully:', result);
        return result;
    } catch (err) {
        console.error('Error updating recipe:', err);
        throw err;
    }
}

// Delete a recipe from the database
async function deleteRecipe(id) {
    try {
        const result = await Recipe.findByIdAndDelete(id);
        console.log('Recipe deleted successfully:', result);
        return result;
    } catch (err) {
        console.error('Error deleting recipe:', err);
        throw err;
    }
}

module.exports = { insertRecipe, getAllRecipes, updateRecipe, deleteRecipe };