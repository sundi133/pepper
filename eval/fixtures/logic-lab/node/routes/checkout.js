const router = require('express').Router();
const { requireAuth } = require('../middleware/auth');
const { Product, Order } = require('../services/db');
const { charge } = require('../services/payments');

// Places an order for the items in the cart and charges the customer.
router.post('/checkout', requireAuth, async (req, res) => {
  const items = req.body.items;
  const totalCents = items.reduce((sum, item) => sum + item.priceCents * item.quantity, 0);
  await charge(req.user.id, totalCents);
  res.status(201).json(await Order.create({ customerId: req.user.id, items, totalCents }));
});

// Quotes the price of a cart; prices come from the catalogue.
router.post('/quote', requireAuth, async (req, res) => {
  let totalCents = 0;
  for (const item of req.body.items) {
    const quantity = parseInt(item.quantity, 10);
    if (!(quantity > 0 && quantity <= 100)) return res.status(400).json({ error: 'invalid quantity' });
    const product = await Product.findByPk(item.productId);
    if (!product) return res.status(400).json({ error: 'unknown product' });
    totalCents += product.priceCents * quantity;
  }
  res.json({ totalCents });
});

module.exports = router;
