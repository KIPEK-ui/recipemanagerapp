const mariadb = require('mariadb');
const pool = mariadb.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'recipes',
    allowPublicKeyRetrieval: true,
    connectionLimit: 20,
    acquireTimeout: 60000
});

// Create the Recipes table if it doesn't exist
async function createTable() {
    let conn;
    try {
        conn = await pool.getConnection();
        await conn.query(`
            CREATE TABLE IF NOT EXISTS Recipes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                ingredients TEXT NOT NULL,
                instructions TEXT NOT NULL,
                image VARCHAR(255) NOT NULL
            )
        `);
        console.log('Recipes table created successfully');
    } catch (err) {
        console.error('Error creating Recipes table:', err);
    } finally {
        if (conn) conn.end();
    }
}

// Insert a new recipe into the database
async function insertRecipe(recipe) {
    let conn;
    try {
        conn = await pool.getConnection();
        const result = await conn.query(`
            INSERT INTO Recipes (name, ingredients, instructions, image)
            VALUES (?, ?, ?, ?)
        `, [recipe.name, recipe.ingredients, recipe.instructions, recipe.image]);
        console.log('Recipe inserted successfully:', result);
        return result;
    } catch (err) {
        console.error('Error inserting recipe:', err);
        throw err;
    } finally {
        if (conn) conn.release();
    }
}

// Retrieve all recipes from the database
async function getAllRecipes() {
    let conn;
    try {
        conn = await pool.getConnection();
        const rows = await conn.query("SELECT * FROM Recipes");
        console.log('Recipes fetched successfully:', rows);
        return rows;
    } catch (err) {
        console.error('Error fetching recipes:', err);
        throw err;
    } finally {
        if (conn) conn.release();
    }
}

// Update a recipe in the database
async function updateRecipe(id, recipe) {
    let conn;
    try {
        conn = await pool.getConnection();
        const result = await conn.query(`
            UPDATE Recipes
            SET name = ?, ingredients = ?, instructions = ?, image = COALESCE(?, image)
            WHERE id = ?
        `, [recipe.name, recipe.ingredients, recipe.instructions, recipe.image, id]);
        console.log('Recipe updated successfully:', result);
        return result;
    } catch (err) {
        console.error('Error updating recipe:', err);
        throw err;
    } finally {
        if (conn) conn.release();
    }
}

// Delete a recipe from the database
async function deleteRecipe(id) {
    let conn;
    try {
        conn = await pool.getConnection();
        const result = await conn.query("DELETE FROM Recipes WHERE id = ?", [id]);
        console.log('Recipe deleted successfully:', result);
        return result;
    } catch (err) {
        console.error('Error deleting recipe:', err);
        throw err;
    } finally {
        if (conn) conn.release();
    }
}

// Initialize the database
createTable();

module.exports = { insertRecipe, getAllRecipes, updateRecipe, deleteRecipe };