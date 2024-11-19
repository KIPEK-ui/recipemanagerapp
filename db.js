// Import required modules
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Get MongoDB URL from environment variables
const MONGOURL = process.env.MONGO_URL;

// Connect to MongoDB
mongoose.connect(MONGOURL, {})
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch(err => {
        console.error('Error connecting to MongoDB:', err);
    });

// Define the Recipe schema
const recipeSchema = new mongoose.Schema({
    name: { type: String, required: true }, // Recipe name
    ingredients: { type: String, required: true }, // Ingredients list
    instructions: { type: String, required: true }, // Cooking instructions
    image: { type: String, required: true }, // Image URL
    category: { type: String, required: true }, // Recipe category
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true } // Reference to the user who created the recipe
});

// Define the User schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true }, // User email
    password: { type: String, required: function() { return !this.googleId && !this.githubId; } }, // User password, required if no Google or GitHub ID
    googleId: { type: String }, // Google ID for OAuth
    githubId: { type: String } // GitHub ID for OAuth
});

// Hash password before saving if it is provided
userSchema.pre('save', async function(next) {
    if (this.password && this.isModified('password')) {
        const salt = await bcrypt.genSalt(10); // Generate salt for hashing
        this.password = await bcrypt.hash(this.password, salt); // Hash the password
    }
    next(); // Proceed to save
});

// Create the models
const Recipe = mongoose.model('Recipe', recipeSchema);
const User = mongoose.model('User', userSchema);

// Function to insert a new user
const insertUser = async(email, password) => {
    try {
        const salt = await bcrypt.genSalt(10); // Generate salt for hashing
        const hashedPassword = await bcrypt.hash(password, salt); // Hash the password
        const newUser = new User({ email, password: hashedPassword }); // Create new user instance
        await newUser.save(); // Save user to database
        return newUser; // Return the saved user
    } catch (err) {
        console.error('Error inserting user:', err);
        throw err; // Throw error if any
    }
};

// Insert a new recipe into the database
async function insertRecipe(recipe) {
    try {
        const newRecipe = new Recipe(recipe); // Create new recipe instance
        const result = await newRecipe.save(); // Save recipe to database
        console.log('Recipe inserted successfully:', result);
        return result; // Return the saved recipe
    } catch (err) {
        console.error('Error inserting recipe:', err);
        throw err; // Throw error if any
    }
}

// Retrieve all recipes from the database
async function getAllRecipes() {
    try {
        const recipes = await Recipe.find().populate('user').populate('image'); // Find all recipes and populate user and image fields
        console.log('Recipes fetched successfully:', recipes);
        return recipes; // Return all recipes
    } catch (err) {
        console.error('Error fetching recipes:', err);
        throw err; // Throw error if any
    }
}

// Retrieve a recipe by ID
async function getRecipeById(id) {
    try {
        const recipe = await Recipe.findById(id).populate('user').populate('image'); // Find recipe by ID and populate user and image fields
        console.log('Recipe fetched successfully:', recipe);
        return recipe; // Return the recipe
    } catch (err) {
        console.error('Error fetching recipe:', err);
        throw err; // Throw error if any
    }
}

// Retrieve recipes by category
async function getRecipesByCategory(category) {
    try {
        const recipes = await Recipe.find({ category }).populate('user').populate('image'); // Find recipes by category and populate user and image fields
        console.log('Recipes fetched successfully:', recipes);
        return recipes; // Return recipes by category
    } catch (err) {
        console.error('Error fetching recipes:', err);
        throw err; // Throw error if any
    }
}

// Retrieve recipes by user
async function getRecipesByUser(userId) {
    try {
        const recipes = await Recipe.find({ user: userId }).populate('user').populate('image'); // Find recipes by user ID and populate user and image fields
        console.log('Recipes fetched successfully:', recipes);
        return recipes; // Return recipes by user
    } catch (err) {
        console.error('Error fetching recipes:', err);
        throw err; // Throw error if any
    }
}

// Update a recipe in the database
async function updateRecipe(id, recipe, userId) {
    try {
        const existingRecipe = await Recipe.findById(id); // Find the recipe by ID
        if (!existingRecipe) {
            console.log('Recipe not found:', id);
            return null;
        }
        if (existingRecipe.user.toString() !== userId) {
            console.log('User not authorized to update this recipe');
            throw new Error('User not authorized to update this recipe');
        }
        const result = await Recipe.findByIdAndUpdate(id, recipe, { new: true }).populate('user').populate('image'); // Update the recipe and populate user and image fields
        console.log('Recipe updated successfully:', result);
        return result; // Return the updated recipe
    } catch (err) {
        console.error('Error updating recipe:', err);
        throw err; // Throw error if any
    }
}

// Delete a recipe from the database
async function deleteRecipe(id, userId) {
    // Check if the provided id is a valid MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(id)) {
        console.error('Invalid ObjectId:', id);
        throw new Error('Invalid ObjectId');
    }

    try {
        const existingRecipe = await Recipe.findById(id); // Find the recipe by ID
        if (!existingRecipe) {
            console.log('Recipe not found:', id);
            return null;
        }
        if (existingRecipe.user.toString() !== userId) {
            console.log('User not authorized to delete this recipe');
            throw new Error('User not authorized to delete this recipe');
        }
        const result = await Recipe.findByIdAndDelete(id); // Delete the recipe
        console.log('Recipe deleted successfully:', result);
        return result; // Return the deleted recipe
    } catch (err) {
        console.error('Error deleting recipe:', err);
        throw err; // Throw error if any
    }
}

// Export the models and functions
module.exports = { User, Recipe, insertUser, insertRecipe, getAllRecipes, getRecipeById, getRecipesByCategory, getRecipesByUser, updateRecipe, deleteRecipe };