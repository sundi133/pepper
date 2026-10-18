const router = require('express').Router();
const { requireAuth } = require('../middleware/auth');
const { Invoice } = require('../services/db');
const { exportQueue } = require('../jobs/export-job');

router.post('/invoices', requireAuth, async (req, res) => {
  const invoice = await Invoice.create({
    customer: req.body.customer,
    amountCents: req.body.amountCents,
    ownerId: req.user.id,
  });
  res.status(201).json(invoice);
});

router.get('/invoices/:id', requireAuth, async (req, res) => {
  const invoice = await Invoice.findOne({ where: { id: req.params.id, ownerId: req.user.id } });
  if (!invoice) return res.status(404).end();
  res.json(invoice);
});

router.put('/invoices/:id', requireAuth, async (req, res) => {
  const invoice = await Invoice.findOne({ where: { id: req.params.id } });
  if (!invoice) return res.status(404).end();
  await invoice.update({ customer: req.body.customer, amountCents: req.body.amountCents });
  res.json(invoice);
});

router.delete('/invoices/:id', requireAuth, async (req, res) => {
  const deleted = await Invoice.destroy({ where: { id: req.params.id, ownerId: req.user.id } });
  if (!deleted) return res.status(404).end();
  res.status(204).end();
});

// Exports one invoice as a PDF e-mailed to the given address.
router.post('/invoices/:id/export', requireAuth, async (req, res) => {
  await exportQueue.add('export', { invoiceId: req.params.id, email: req.body.email });
  res.status(202).json({ queued: true });
});

// Sends the invoice to its customer; the job re-checks the owner.
router.post('/invoices/:id/send', requireAuth, async (req, res) => {
  await exportQueue.add('send', { invoiceId: req.params.id, ownerId: req.user.id });
  res.status(202).json({ queued: true });
});

module.exports = router;
