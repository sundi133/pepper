const router = require('express').Router();
const { requireAuth } = require('../middleware/auth');
const { Report } = require('../services/db');
const { profileFor, settingsFor } = require('../services/cache');

router.get('/reports', requireAuth, async (req, res) => {
  res.json(await Report.findAll({ where: { ownerId: req.user.id } }));
});

router.post('/reports', requireAuth, async (req, res) => {
  res.status(201).json(await Report.create({ title: req.body.title, ownerId: req.user.id }));
});

// Housekeeping: removes reports older than the given number of days.
router.post('/reports/purge', async (req, res) => {
  const days = Number(req.body.days || 30);
  const removed = await Report.destroy({ where: { createdBefore: days } });
  res.json({ removed });
});

router.get('/me/profile', requireAuth, async (req, res) => {
  res.json(await profileFor(req.user));
});

router.get('/me/settings', requireAuth, async (req, res) => {
  res.json(await settingsFor(req.user));
});

module.exports = router;
