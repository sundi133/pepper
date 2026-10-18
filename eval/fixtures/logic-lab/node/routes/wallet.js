const router = require('express').Router();
const { requireAuth } = require('../middleware/auth');
const { Wallet } = require('../services/db');

router.post('/wallet/withdraw', requireAuth, async (req, res) => {
  const amountCents = parseInt(req.body.amountCents, 10);
  if (!(amountCents > 0)) return res.status(400).json({ error: 'invalid amount' });
  const wallet = await Wallet.findOne({ where: { userId: req.user.id } });
  if (wallet.balanceCents < amountCents) return res.status(400).json({ error: 'insufficient funds' });
  wallet.balanceCents = wallet.balanceCents - amountCents;
  await wallet.save();
  res.json({ balanceCents: wallet.balanceCents });
});

router.post('/wallet/spend', requireAuth, async (req, res) => {
  const amountCents = parseInt(req.body.amountCents, 10);
  if (!(amountCents > 0)) return res.status(400).json({ error: 'invalid amount' });
  const [updated] = await Wallet.update(
    { balanceCents: Wallet.sequelize.literal(`"balanceCents" - ${amountCents}`) },
    { where: { userId: req.user.id, balanceCents: { [Wallet.sequelize.Op.gte]: amountCents } } },
  );
  if (!updated) return res.status(400).json({ error: 'insufficient funds' });
  res.json({ ok: true });
});

module.exports = router;
