//---------------------------------------------------IMPORTS----------------------------------------------------------------------
const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const swaggerOptions = {
    swaggerDefinition: {
        openapi: '3.0.0',
        info: {
            title: 'Recipe Manager API',
            version: '1.0.0',
            description: 'API for managing recipes and users'
        },
        servers: [{
                url: 'http://localhost:85',
                description: 'Local server'
            },
            {
                url: 'https://recipemanagerapp.vercel.app',
                description: 'Production server'
            }

        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        },
        security: [{
            bearerAuth: []
        }]
    },
    apis: ['./routes.js']
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);

module.exports = (app) => {
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));
};