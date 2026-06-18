'use strict';

const { Pool } = require('pg');

const pool = new Pool({
    host:     process.env.DB_HOST     || 'localhost',
    port:     parseInt(process.env.DB_PORT || '5432'),
    database: process.env.DB_NAME     || 'syntex_db',
    user:     process.env.DB_USER     || 'syntex_admin',
    password: process.env.DB_PASS     || 'Synx@2024!Prod',
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

pool.on('error', (err) => {
    console.error('[DB] Unexpected pool error:', err.message);
});

module.exports = {
    query: (text, params) => pool.query(text, params),
    pool,
};
