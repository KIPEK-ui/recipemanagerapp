require('dotenv').config();
const http = require('http');
const express = require('express');
const routes = require('./routes');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads')); // Serve static files from the uploads directory
app.use('/', routes);

const port = process.env.PORT || 83;
http.createServer(app).listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});