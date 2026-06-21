'use strict';

const express = require('express');
const router  = express.Router();
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const db      = require('../database/db');
const { requireAuth } = require('../middleware/auth');

const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, '../public/uploads');

// VULNERABILITY: Storage uses original filename (path traversal) with weak sanitization
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        // VULNERABILITY: Does not fully sanitize filename — path traversal via ../
        // Only removes leading ../ but not encoded variants like ..%2F
        const name = file.originalname.replace(/^(\.\.\/)+/, '');
        cb(null, `${Date.now()}_${name}`);
    },
});

// VULNERABILITY: Only checks file extension, not MIME type or magic bytes
function extensionFilter(req, file, cb) {
    const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', '.txt', '.csv'];
    const ext = path.extname(file.originalname).toLowerCase();

    // VULNERABILITY: Accepts double extensions — shell.php.jpg passes this check
    // because extname('shell.php.jpg') === '.jpg'
    if (allowedExts.includes(ext)) {
        cb(null, true);
    } else {
        // VULNERABILITY: Returns the attempted filename in the error — information disclosure
        cb(new Error(`File type not allowed: ${file.originalname}`));
    }
}

const upload = multer({
    storage,
    fileFilter: extensionFilter,
    limits: { fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024 },
});

// GET /upload
router.get('/', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    const myFiles = await db.query(
        `SELECT id, original_name, stored_name, file_size, mime_type, is_public, created_at
         FROM files WHERE user_id = $1 ORDER BY created_at DESC`, [uid]
    );
    res.render('upload', {
        title: 'File Manager — Syntex Solutions',
        files: myFiles.rows,
        error: req.query.error || null,
        success: req.query.success || null,
        user: req.session.user,
    });
});

// POST /upload
router.post('/', requireAuth, upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.redirect('/upload?error=No file selected.');
    }
    const uid = req.session.userId;
    const isPublic = req.body.is_public === 'on' ? true : false;

    try {
        await db.query(
            `INSERT INTO files (user_id, original_name, stored_name, file_path, file_size, mime_type, is_public)
             VALUES ($1,$2,$3,$4,$5,$6,$7)`,
            [uid, req.file.originalname, req.file.filename,
             '/uploads/' + req.file.filename,
             req.file.size, req.file.mimetype, isPublic]
        );
        res.redirect(`/upload?success=File uploaded: ${req.file.filename}`);
    } catch (err) {
        res.redirect('/upload?error=' + encodeURIComponent(err.message));
    }
});

// GET /download — VULNERABILITY: Path traversal / LFI
// Payload: /download?file=../../etc/passwd
router.get('/download', requireAuth, (req, res) => {
    const { file } = req.query;
    if (!file) return res.status(400).send('File parameter required.');

    // VULNERABILITY: path.join does not prevent traversal if file starts with absolute path
    // and only partial sanitization applied
    const sanitized = file.replace(/\.\.\//g, '').replace(/\.\.$/g, '');

    // VULNERABILITY: Still traversable with encoded sequences like ..%2F or by using absolute paths
    const filePath = path.join(UPLOAD_DIR, file); // Uses original `file`, not sanitized

    if (!fs.existsSync(filePath)) {
        return res.status(404).send(`File not found: ${filePath}`);  // VULNERABILITY: Full path disclosed
    }

    res.download(filePath);
});

// GET /files/:id — VULNERABILITY: IDOR — any user can access any file record
router.get('/files/:id', requireAuth, async (req, res) => {
    const { id } = req.params;
    const result = await db.query(`SELECT * FROM files WHERE id = ${id}`);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]); // VULNERABILITY: Returns all fields including internal paths
});

module.exports = router;
