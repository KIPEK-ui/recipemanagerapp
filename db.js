const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Joi = require('joi'); // For validation

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
    name: { type: String, required: true },
    ingredients: { type: String, required: true },
    instructions: { type: String, required: true },
    category: { type: String, required: true },
    image: { type: mongoose.Schema.Types.ObjectId, ref: 'File', required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true }
});

// Define the User schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: function() { return !this.googleId && !this.githubId; } },
    googleId: { type: String },
    githubId: { type: String },
    firstName: { type: String },
    lastName: { type: String },
    gender: { type: String, enum: ['Male', 'Female', 'Other'], required: false } // Ensure gender is required
});

// Indexing for optimization
recipeSchema.index({ category: 1 });
recipeSchema.index({ user: 1 });

// Hash password before saving if it is provided
userSchema.pre('save', async function(next) {
    if (this.password && this.isModified('password')) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }
    next();
});

// Create the models
const Recipe = mongoose.model('Recipe', recipeSchema);
const User = mongoose.model('User', userSchema);

// Validation schemas
const userValidationSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    googleId: Joi.string().optional(),
    githubId: Joi.string().optional(),
    firstName: Joi.string().optional(),
    lastName: Joi.string().optional(),
    gender: Joi.string().valid('Male', 'Female', 'Other').required() // Ensure gender validation
});

const recipeValidationSchema = Joi.object({
    name: Joi.string().required(),
    ingredients: Joi.string().required(),
    instructions: Joi.string().required(),
    category: Joi.string().required(),
    image: Joi.string().required(),
    user: Joi.string().required(),
    firstName: Joi.string().required(),
    lastName: Joi.string().required()
});

// Function to insert a new user
const insertUser = async(email, password) => {
    try {
        const { error } = userValidationSchema.validate({ email, password });
        if (error) throw new Error(error.details[0].message);

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
async function insertRecipe(recipe, userId) {
    try {
        const { error } = recipeValidationSchema.validate({...recipe, user: userId });
        if (error) throw new Error(error.details[0].message);

        const newRecipe = new Recipe({
            ...recipe,
            user: userId
        });
        const result = await newRecipe.save();
        console.log('Recipe inserted successfully:', result);
        return result;
    } catch (err) {
        console.error('Error inserting recipe:', err);
        throw err;
    }
}

// Retrieve recipes by user
async function getRecipesByUser(userId) {
    try {
        const recipes = await Recipe.find({ user: userId }).populate('user').populate('image');
        console.log('Recipes fetched successfully:', recipes);
        return recipes;
    } catch (err) {
        console.error('Error fetching recipes:', err);
        throw err;
    }
}

// Retrieve all recipes with pagination
async function getAllRecipes(page = 1, limit = 3) {
    try {
        const recipes = await Recipe.find()
            .populate('user')
            .populate('image')
            .skip((page - 1) * limit)
            .limit(limit);
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
        const recipe = await Recipe.findById(id).populate('user').populate('image');
        console.log('Recipe fetched successfully:', recipe);
        return recipe;
    } catch (err) {
        console.error('Error fetching recipe:', err);
        throw err;
    }
}

// Retrieve recipes by category with pagination
async function getRecipesByCategory(category, page = 1, limit = 3) {
    try {
        const recipes = await Recipe.find({ category })
            .populate('user')
            .populate('image')
            .skip((page - 1) * limit)
            .limit(limit);
        console.log('Recipes fetched successfully:', recipes);
        return recipes;
    } catch (err) {
        console.error('Error fetching recipes:', err);
        throw err;
    }
}

// Update a recipe in the database
async function updateRecipe(id, recipe, userId) {
    try {
        const { error } = recipeValidationSchema.validate({...recipe, user: userId });
        if (error) throw new Error(error.details[0].message);

        const existingRecipe = await Recipe.findById(id);
        if (!existingRecipe) {
            console.log('Recipe not found:', id);
            return null;
        }
        if (existingRecipe.user.toString() !== userId) {
            console.log('User not authorized to update this recipe');
            throw new Error('User not authorized to update this recipe');
        }
        const result = await Recipe.findByIdAndUpdate(id, recipe, { new: true }).populate('user').populate('image');
        console.log('Recipe updated successfully:', result);
        return result;
    } catch (err) {
        console.error('Error updating recipe:', err);
        throw err;
    }
}

// Delete a recipe from the database
async function deleteRecipe(id, userId) {
    if (!mongoose.Types.ObjectId.isValid(id)) {
        console.error('Invalid ObjectId:', id);
        throw new Error('Invalid ObjectId');
    }

    try {
        const existingRecipe = await Recipe.findById(id);
        if (!existingRecipe) {
            console.log('Recipe not found:', id);
            return null;
        }
        if (existingRecipe.user.toString() !== userId) {
            console.log('User not authorized to delete this recipe');
            throw new Error('User not authorized to delete this recipe');
        }
        const result = await Recipe.findByIdAndDelete(id);
        console.log('Recipe deleted successfully:', result);
        return result;
    } catch (err) {
        console.error('Error deleting recipe:', err);
        throw err;
    }
}

// Export the models and functions
module.exports = {
    User,
    Recipe,
    insertUser,
    insertRecipe,
    getAllRecipes,
    getRecipeById,
    getRecipesByCategory,
    getRecipesByUser,
    updateRecipe,
    deleteRecipe
};