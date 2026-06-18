'use strict';

const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { requireAuth } = require('../middleware/auth');

// GET /blog
router.get('/', async (req, res) => {
    const { category } = req.query;
    let query = `SELECT bp.id, bp.title, bp.slug, bp.excerpt, bp.category, bp.tags,
                        bp.views, bp.created_at, u.username as author, u.first_name, u.last_name
                 FROM blog_posts bp JOIN users u ON u.id = bp.author_id
                 WHERE bp.status = 'published'`;
    if (category) query += ` AND bp.category = '${category}'`; // VULNERABILITY: SQLi
    query += ` ORDER BY bp.created_at DESC`;

    try {
        const result = await db.query(query);
        const catResult = await db.query(`SELECT DISTINCT category FROM blog_posts WHERE status='published' ORDER BY category`);
        res.render('blog', {
            title: 'Knowledge Base — Syntex Solutions',
            posts: result.rows,
            categories: catResult.rows.map(r => r.category),
            activeCategory: category || null,
            user: req.session.user || null,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user || null });
    }
});

// GET /blog/:slug
router.get('/:slug', async (req, res) => {
    const { slug } = req.params;
    try {
        // VULNERABILITY: SQLi via slug
        const postResult = await db.query(
            `SELECT bp.*, u.username as author, u.first_name, u.last_name, u.avatar as author_avatar
             FROM blog_posts bp JOIN users u ON u.id = bp.author_id
             WHERE bp.slug = '${slug}' AND bp.status = 'published'`
        );

        if (postResult.rows.length === 0) {
            return res.status(404).render('404', { title: 'Not Found', user: req.session.user || null });
        }

        const post = postResult.rows[0];
        await db.query(`UPDATE blog_posts SET views = views + 1 WHERE id = $1`, [post.id]);

        // VULNERABILITY: Comments fetched with no output encoding in template (<%- ... %>)
        const commentsResult = await db.query(
            `SELECT c.id, c.author_name, c.content, c.created_at, u.avatar
             FROM comments c LEFT JOIN users u ON u.id = c.user_id
             WHERE c.post_id = ${post.id} AND c.is_approved = true ORDER BY c.created_at ASC`
        );

        res.render('post-detail', {
            title: post.title + ' — Syntex Solutions',
            post,
            comments: commentsResult.rows,
            user: req.session.user || null,
        });
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user || null });
    }
});

// POST /blog/:id/comment — VULNERABILITY: Stored XSS — content stored unescaped
router.post('/:id/comment', requireAuth, async (req, res) => {
    const { id } = req.params;
    const { content } = req.body;
    const uid  = req.session.userId;
    const name = req.session.username;

    try {
        // VULNERABILITY: No sanitization — stored XSS
        // VULNERABILITY: SQLi via direct interpolation
        await db.query(
            `INSERT INTO comments (post_id, user_id, author_name, content)
             VALUES (${id}, ${uid}, '${name}', '${content}')`
        );

        // Get slug to redirect back
        const slugR = await db.query(`SELECT slug FROM blog_posts WHERE id = ${id}`);
        const slug  = slugR.rows[0]?.slug || id;
        res.redirect(`/blog/${slug}#comments`);
    } catch (err) {
        res.render('error', { title: 'Error', message: err.message, status: 500, user: req.session.user });
    }
});

module.exports = router;
