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

// Define the User schema
const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
});


// Create the models
const Recipe = mongoose.model('Recipe', recipeSchema);
const User = mongoose.model('User', userSchema);

// Function to insert a new user
const insertUser = async(email, password) => {
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();
        return newUser;
    } catch (err) {
        console.error('Error inserting user:', err);
        throw err;
    }
};
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
        const recipes = await Recipe.find().populate('image');
        console.log('Recipes fetched successfully:', recipes);
        return recipes;
    } catch (err) {
        console.error('Error fetching recipes:', err);
        throw err;
    }
}

// Retrieve a recipe by ID
async function getRecipeById(id) {
    try {
        const recipe = await Recipe.findById(id).populate('image');
        console.log('Recipe fetched successfully:', recipe);
        return recipe;
    } catch (err) {
        console.error('Error fetching recipe:', err);
        throw err;
    }
}

// Retrieve recipes by category
async function getRecipesByCategory(category) {
    try {
        const recipes = await Recipe.find({ category }).populate('image');
        console.log('Recipes fetched successfully:', recipes);
        return recipes;
    } catch (err) {
        console.error('Error fetching recipes:', err);
        throw err;
    }
}

// Retrieve recipes by user
async function getRecipesByUser(userId) {
    try {
        const recipes = await Recipe.find({ user: userId }).populate('image');
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
        const result = await Recipe.findByIdAndUpdate(id, recipe, { new: true }).populate('image');
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

module.exports = { User, insertUser, insertRecipe, getAllRecipes, getRecipeById, getRecipesByCategory, getRecipesByUser, updateRecipe, deleteRecipe };