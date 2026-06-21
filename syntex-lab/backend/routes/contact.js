'use strict';

const express = require('express');
const router  = express.Router();
const { exec } = require('child_process');
const { requireAuth } = require('../middleware/auth');

router.get('/', (req, res) => {
    res.render('contact', {
        title: 'Contact Support — Syntex Solutions',
        success: null, error: null,
        user: req.session.user || null,
    });
});

// POST /contact
// VULNERABILITY: Command injection — name field interpolated directly into shell command
// EDUCATIONAL NOTE: This demonstrates OS command injection (OWASP A03).
// In this lab the command only writes to /tmp inside Docker.
// Real-world impact: full RCE on unpatched systems.
router.post('/', (req, res) => {
    const { name, email, subject, message, department } = req.body;

    if (!name || !email || !message) {
        return res.render('contact', {
            title: 'Contact Support',
            error: 'Name, email and message are required.',
            success: null, user: req.session.user || null,
        });
    }

    // VULNERABILITY: Command injection — user-controlled `name` and `subject` concatenated into shell
    // Payload example: name = "test; id > /tmp/pwned.txt"
    const logCmd = `echo "[$(date)] Contact from: ${name} <${email}> | Subject: ${subject}" >> /tmp/contact_log.txt`;

    exec(logCmd, (err, stdout, stderr) => {
        if (err) {
            // VULNERABILITY: stderr exposed to client
            return res.render('contact', {
                title: 'Contact Support',
                error: 'Submission error: ' + stderr,
                success: null, user: req.session.user || null,
            });
        }

        res.render('contact', {
            title: 'Contact Support',
            success: `Thank you, ${name}. Your message has been received. Reference: REF-${Date.now()}`,
            error: null, user: req.session.user || null,
        });
    });
});

module.exports = router;
