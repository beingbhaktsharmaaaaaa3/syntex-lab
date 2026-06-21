'use strict';

const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { requireAuth } = require('../middleware/auth');

// GET /orders
router.get('/', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    try {
        const result = await db.query(
            `SELECT o.*, p.name as product_name, p.sku
             FROM orders o JOIN products p ON p.id = o.product_id
             WHERE o.user_id = $1 ORDER BY o.created_at DESC`, [uid]
        );
        res.render('orders', {
            title: 'My Orders — Syntex Solutions',
            orders: result.rows,
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// GET /orders/:id — VULNERABILITY: IDOR — any authenticated user can view any order
router.get('/:id', requireAuth, async (req, res) => {
    const { id } = req.params;
    try {
        // VULNERABILITY: No check that order belongs to req.session.userId
        const result = await db.query(
            `SELECT o.*, p.name as product_name, p.sku, p.description as product_desc,
                    u.username, u.email, u.first_name, u.last_name, u.phone
             FROM orders o
             JOIN products p ON p.id = o.product_id
             JOIN users u ON u.id = o.user_id
             WHERE o.id = ${id}`
        );

        if (result.rows.length === 0) {
            return res.status(404).render('404', { title: 'Not Found', user: req.session.user });
        }

        res.render('order-detail', {
            title: `Order ${result.rows[0].invoice_number} — Syntex Solutions`,
            order: result.rows[0],
            user: req.session.user,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// POST /orders — VULNERABILITY: Business logic — negative quantity, price manipulation
router.post('/', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    // VULNERABILITY: unit_price accepted from client — attacker can send any price
    const { product_id, quantity, unit_price, shipping_address, notes } = req.body;

    try {
        const prodResult = await db.query(`SELECT * FROM products WHERE id = $1`, [product_id]);
        if (prodResult.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const product = prodResult.rows[0];

        // VULNERABILITY: Uses client-supplied unit_price instead of DB price
        const price      = parseFloat(unit_price) || product.price;
        const qty        = parseInt(quantity);
        // VULNERABILITY: No check for negative quantity — negative total = credit
        const totalPrice = price * qty;

        const crypto   = require('crypto');
        const invoiceN = 'INV-' + Date.now();
        const licenseK = crypto.randomBytes(8).toString('hex').toUpperCase();

        const result = await db.query(
            `INSERT INTO orders (user_id, product_id, quantity, unit_price, total_price,
                                 invoice_number, license_key, shipping_address, notes)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
            [uid, product_id, qty, price, totalPrice, invoiceN, licenseK, shipping_address, notes]
        );

        res.redirect(`/orders/${result.rows[0].id}`);
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

// POST /orders/apply-coupon — VULNERABILITY: Coupon reuse, no per-user check
router.post('/apply-coupon', requireAuth, async (req, res) => {
    const { code, order_id } = req.body;

    try {
        // VULNERABILITY: No check whether this user already used this coupon
        const couponResult = await db.query(
            `SELECT * FROM coupons WHERE code = '${code}' AND is_active = true`
        );

        if (couponResult.rows.length === 0) {
            return res.json({ success: false, error: 'Invalid or inactive coupon code.' });
        }

        const coupon = couponResult.rows[0];

        // VULNERABILITY: max_uses check is present but race condition allows bypass
        if (coupon.used_count >= coupon.max_uses) {
            return res.json({ success: false, error: 'Coupon has reached its maximum uses.' });
        }

        // VULNERABILITY: No ownership check on order_id
        const orderResult = await db.query(`SELECT * FROM orders WHERE id = ${order_id}`);
        if (orderResult.rows.length === 0) {
            return res.json({ success: false, error: 'Order not found.' });
        }

        const order    = orderResult.rows[0];
        const discount = (order.unit_price * order.quantity * coupon.discount_percent) / 100;
        const newTotal = order.total_price - discount;

        await db.query(`UPDATE orders SET coupon_code='${code}', discount=${discount}, total_price=${newTotal} WHERE id=${order_id}`);
        await db.query(`UPDATE coupons SET used_count = used_count + 1 WHERE code = '${code}'`);

        res.json({ success: true, discount, new_total: newTotal, message: `${coupon.discount_percent}% discount applied.` });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

module.exports = router;
