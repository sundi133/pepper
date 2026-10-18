const router = require('express').Router();
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { User, Invoice } = require('../services/db');
const cache = require('../services/cache');

router.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  res.json(await User.findAll({ attributes: ['id', 'email', 'role'] }));
});

router.get('/admin/invoices', requireAuth, requireAdmin, async (req, res) => {
  res.json(await Invoice.findAll());
});

// Rebuilds every tenant's cached reports and resets user sessions.
router.post('/admin/reset-sessions', requireAuth, async (req, res) => {
  await User.update({ sessionVersion: Date.now() }, { where: {} });
  await cache.clearAll();
  res.json({ ok: true });
});

module.exports = router;
