const mongoose = require('mongoose');

const MONGOURL = process.env.MONGO_URL;

let cached = global.mongoose;

if (!cached) {
    cached = global.mongoose = { conn: null, promise: null };
}

async function connectToDatabase() {
    if (cached.conn) {
        return cached.conn;
    }

    if (!cached.promise) {
        const opts = {
            bufferCommands: false,
        };

        cached.promise = mongoose.connect(MONGOURL, opts).then((mongoose) => {
            return mongoose;
        });
    }

    cached.conn = await cached.promise;
    return cached.conn;
}




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
    if (!mongoose.Types.ObjectId.isValid(id)) {
        console.error('Invalid ObjectId:', id);
        throw new Error('Invalid ObjectId');
    }

    try {
        const result = await Recipe.findByIdAndDelete(id);
        if (!result) {
            console.log('Recipe not found:', id);
            return null;
        }
        console.log('Recipe deleted successfully:', result);
        return result;
    } catch (err) {
        console.error('Error deleting recipe:', err);
        throw err;
    }
}


module.exports = { connectToDatabase, insertRecipe, getAllRecipes, updateRecipe, deleteRecipe };