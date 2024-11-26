const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'sxglxt',
  password: '18787742572',
  port: 5432,
});

module.exports = pool;