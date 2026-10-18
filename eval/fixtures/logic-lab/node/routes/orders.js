const router = require('express').Router();
const { requireAuth } = require('../middleware/auth');
const { Order, OrderNote } = require('../services/db');

async function getOrder(req, res) {
  const order = await Order.findOne({ where: { id: req.params.id, customerId: req.user.id } });
  if (!order) return res.status(404).end();
  return res.json(order);
}

async function getOrderNotes(req, res) {
  const notes = await OrderNote.findAll({ where: { orderId: req.params.id } });
  return res.json(notes);
}

router.get('/orders/:id', requireAuth, getOrder);
router.get('/orders/:id/notes', getOrderNotes, requireAuth);

module.exports = router;
