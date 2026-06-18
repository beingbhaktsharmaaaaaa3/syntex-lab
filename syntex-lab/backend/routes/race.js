'use strict';

// ── Race Condition Module ─────────────────────────────────────────
// Vulnerabilities:
//   1. Coupon reuse via parallel requests (no DB lock)
//   2. Reward claim double-spend
//   3. Wallet balance negative via concurrent withdrawals
//   4. Free item claim via parallel checkout
//
// Tools: Burp Suite Turbo Intruder, ffuf, ab, custom Python script

const express = require('express');
const router  = express.Router();
const db      = require('../database/db');
const { requireAuth } = require('../middleware/auth');

// In-memory "processing" lock (intentionally NOT thread-safe)
const processing = new Set();

// ── Wallet balance endpoints ─────────────────────────────────────
router.get('/wallet', requireAuth, async (req, res) => {
    const uid = req.session.userId;
    const r = await db.query(`SELECT wallet_balance, wallet_bonus FROM users WHERE id=$1`, [uid]);
    const user = r.rows[0] || { wallet_balance: 100.00, wallet_bonus: 0 };
    res.json({
        user_id: uid,
        balance: parseFloat(user.wallet_balance || 100),
        bonus:   parseFloat(user.wallet_bonus   || 0),
        lab_note: 'RACE CONDITION: Try withdrawing simultaneously with Turbo Intruder',
    });
});

// VULNERABILITY: Race condition on withdrawal — no SELECT FOR UPDATE
// Burp Turbo Intruder payload:
//   POST /race/withdraw {"amount": 90}  × 20 concurrent requests
//   → Balance goes negative if requests arrive before DB update completes
router.post('/withdraw', requireAuth, async (req, res) => {
    const uid    = req.session.userId;
    const amount = parseFloat(req.body.amount) || 0;

    if (amount <= 0) return res.status(400).json({ error: 'Amount must be positive' });

    // VULNERABILITY: Check-then-act race condition (no atomic operation)
    const r = await db.query(`SELECT wallet_balance FROM users WHERE id=$1`, [uid]);
    const balance = parseFloat(r.rows[0]?.wallet_balance || 100);

    // Simulate processing delay (intentional — gives race window)
    await new Promise(resolve => setTimeout(resolve, 50));

    if (balance < amount) {
        return res.status(400).json({ error: 'Insufficient balance', balance });
    }

    // VULNERABILITY: Update happens after check — concurrent requests both pass
    await db.query(
        `UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id=$2`,
        [amount, uid]
    );

    const newBalance = await db.query(`SELECT wallet_balance FROM users WHERE id=$1`, [uid]);
    res.json({
        success:     true,
        withdrawn:   amount,
        new_balance: parseFloat(newBalance.rows[0].wallet_balance),
        message:     'Withdrawal successful',
    });
});

// VULNERABILITY: Race condition — claim free item without proper locking
router.post('/claim-reward', requireAuth, async (req, res) => {
    const uid = req.session.userId;

    // VULNERABILITY: Multiple concurrent requests can all pass this check
    const existing = await db.query(
        `SELECT id FROM reward_claims WHERE user_id=$1 AND claimed_at > NOW() - INTERVAL '1 day'`,
        [uid]
    );

    if (existing.rows.length > 0) {
        return res.status(400).json({ error: 'Already claimed today', claimed_at: existing.rows[0].claimed_at });
    }

    // Artificial delay to widen race window
    await new Promise(r => setTimeout(r, 100));

    try {
        await db.query(
            `INSERT INTO reward_claims (user_id, reward_type, amount) VALUES ($1,'daily_bonus',50.00)`,
            [uid]
        );
        await db.query(`UPDATE users SET wallet_bonus = wallet_bonus + 50 WHERE id=$1`, [uid]);

        res.json({
            success: true,
            reward:  50,
            message: 'Daily bonus claimed! Send parallel requests to claim multiple times.',
        });
    } catch (err) {
        res.status(400).json({ error: 'Claim failed', detail: err.message });
    }
});

// VULNERABILITY: Coupon race — apply same coupon to multiple orders simultaneously
router.post('/apply-coupon-race', requireAuth, async (req, res) => {
    const { coupon_code, order_id } = req.body;
    const uid = req.session.userId;

    // VULNERABILITY: No transaction lock — 20 concurrent requests all see uses < max_uses
    const coupon = await db.query(
        `SELECT * FROM coupons WHERE code=$1 AND is_active=true`, [coupon_code]
    );
    if (!coupon.rows.length) return res.status(404).json({ error: 'Coupon not found' });

    const c = coupon.rows[0];

    // VULNERABILITY: Race condition check
    if (c.used_count >= c.max_uses) {
        return res.status(400).json({ error: 'Coupon exhausted', used: c.used_count, max: c.max_uses });
    }

    // Delay to widen race window
    await new Promise(r => setTimeout(r, 75));

    await db.query(`UPDATE coupons SET used_count = used_count + 1 WHERE code=$1`, [coupon_code]);

    res.json({
        success:      true,
        coupon:       coupon_code,
        discount:     c.discount_percent + '%',
        message:      'Coupon applied. Try sending 50 parallel requests to exhaust max_uses.',
        used_count:   c.used_count + 1,
        max_uses:     c.max_uses,
    });
});

// ── Race condition info page ──────────────────────────────────────
router.get('/info', (req, res) => {
    res.json({
        module:      'Race Condition Lab',
        description: 'Practice concurrent request attacks',
        endpoints: {
            'GET  /race/wallet':              'Check your balance',
            'POST /race/withdraw':            'Withdraw funds (race: send 20 concurrent requests)',
            'POST /race/claim-reward':        'Claim daily reward (race: claim multiple times)',
            'POST /race/apply-coupon-race':   'Apply coupon (race: exhaust coupon uses)',
        },
        turbo_intruder_example: {
            script: `
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=20,
                          requestsPerConnection=1,
                          pipeline=False)
    for i in range(20):
        engine.queue(target.req, None)

def handleResponse(req, interesting):
    table.add(req)
`,
        },
        curl_example: 'for i in $(seq 1 20); do curl -s -X POST http://localhost:3000/race/claim-reward -H "Cookie: SYNTEX_SESS=SESSION" & done; wait',
    });
});

module.exports = router;
