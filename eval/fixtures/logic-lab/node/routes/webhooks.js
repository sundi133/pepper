const router = require('express').Router();
const { verifyWebhookSignature, verifyRefundSignature } = require('../middleware/signature');
const { Account, ProcessedEvent, sequelize } = require('../services/db');

// Payment provider: a payment succeeded, credit the customer's account.
router.post('/webhooks/payments', verifyWebhookSignature, async (req, res) => {
  const event = req.body;
  if (event.type === 'payment.succeeded') {
    const account = await Account.findOne({ where: { customerId: event.data.customerId } });
    account.creditCents += event.data.amountCents;
    await account.save();
  }
  res.status(200).end();
});

// Refund provider: each event is applied once.
router.post('/webhooks/refunds', verifyRefundSignature, async (req, res) => {
  const event = req.body;
  await sequelize.transaction(async (t) => {
    const [, created] = await ProcessedEvent.findOrCreate({ where: { eventId: event.id }, transaction: t });
    if (!created) return;
    const account = await Account.findOne({ where: { customerId: event.data.customerId }, transaction: t, lock: true });
    account.creditCents -= event.data.amountCents;
    await account.save({ transaction: t });
  });
  res.status(200).end();
});

module.exports = router;
