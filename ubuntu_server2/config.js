const mysql = require('mysql');

// Set database connection credentials
const config = {
  host: "localhost",
  port: "3306",
  user: "root",
  password: "Test123$",
  database: 'camera'
};

// Create a MySQL pool
const pool = mysql.createPool(config);

// Export the pool
module.exports = pool;
