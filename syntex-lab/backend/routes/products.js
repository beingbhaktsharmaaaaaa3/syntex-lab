'use strict';

const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { requireAuth } = require('../middleware/auth');

// GET /products — VULNERABILITY: SQLi via category and sort parameters
router.get('/', async (req, res) => {
    const { category, sort, min_price, max_price } = req.query;

    let query = `SELECT id, name, slug, short_desc, price, category, sku, version, license_type, image_url
                 FROM products WHERE is_active = true`;

    // VULNERABILITY: Direct string concatenation in SQL
    if (category && category !== 'all') {
        query += ` AND category = '${category}'`;
    }
    if (min_price) query += ` AND price >= ${min_price}`;
    if (max_price) query += ` AND price <= ${max_price}`;

    // VULNERABILITY: ORDER BY injection — cannot use parameterized queries for ORDER BY
    const sortMap = { price_asc: 'price ASC', price_desc: 'price DESC', name: 'name ASC', newest: 'created_at DESC' };
    // VULNERABILITY: Falls through to raw user input if not in map
    const orderClause = sortMap[sort] || sort || 'created_at DESC';
    query += ` ORDER BY ${orderClause}`;

    try {
        const result = await db.query(query);
        const catResult = await db.query(`SELECT DISTINCT category FROM products WHERE is_active = true ORDER BY category`);

        res.render('products', {
            title: 'Products — Syntex Solutions',
            products: result.rows,
            categories: catResult.rows.map(r => r.category),
            filters: { category, sort, min_price, max_price },
            user: req.session.user || null,
        });
    } catch (err) {
        // VULNERABILITY: Raw SQL error exposed
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user || null });
    }
});

// GET /products/:id — VULNERABILITY: SQLi in product ID
router.get('/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const prodResult = await db.query(
            `SELECT * FROM products WHERE id = ${id} AND is_active = true`
        );

        if (prodResult.rows.length === 0) {
            return res.status(404).render('404', { title: 'Not Found', user: req.session.user || null });
        }

        // VULNERABILITY: SQLi in id for reviews join
        const reviewResult = await db.query(
            `SELECT r.*, u.username FROM reviews r LEFT JOIN users u ON u.id = r.user_id
             WHERE r.product_id = ${id} ORDER BY r.created_at DESC`
        );

        res.render('product-detail', {
            title: prodResult.rows[0].name + ' — Syntex Solutions',
            product: prodResult.rows[0],
            reviews: reviewResult.rows,
            user: req.session.user || null,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user || null });
    }
});

// POST /products/:id/review — VULNERABILITY: Stored XSS in review content
router.post('/:id/review', requireAuth, async (req, res) => {
    const { id } = req.params;
    const { rating, content } = req.body;
    const uid = req.session.userId;
    const username = req.session.username;

    try {
        // VULNERABILITY: No sanitization of content — stored XSS
        await db.query(
            `INSERT INTO reviews (product_id, user_id, author_name, rating, content)
             VALUES (${id}, ${uid}, '${username}', ${rating}, '${content}')`
        );
        res.redirect(`/products/${id}#reviews`);
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

module.exports = router;
