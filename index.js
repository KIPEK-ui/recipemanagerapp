require('dotenv').config();
const http = require('http');
const express = require('express');
const passport = require('passport');
const routes = require('./routes');
const path = require('path');
const app = express();
const swagger = require('./swagger');

// Initialize Swagger
swagger(app);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize Passport
app.use(passport.initialize());

// Serve static files from the 'uploads', 'images', and root directories
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use(express.static(path.join(__dirname)));

// Use routes
app.use('/', routes);

const port = process.env.PORT || 83;
http.createServer(app).listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});