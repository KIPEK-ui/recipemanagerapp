require('dotenv').config();
const http = require('http');
const express = require('express');
const passport = require('passport');
const routes = require('./routes');
const path = require('path');
const cookieParser = require('cookie-parser');
const app = express();
const swagger = require('./swagger');

// Initialize Swagger
swagger(app);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Initialize Passport
app.use(passport.initialize());

// Serve static files from the 'images', and root directories
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use(express.static(path.join(__dirname)));

// Use routes
app.use('/', routes);

// Centralized error-handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

const port = process.env.PORT || 83;
http.createServer(app).listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});