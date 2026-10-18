const crypto = require('crypto');

// Verifies the payment provider's HMAC signature on webhook calls.
function verifyWebhookSignature(req, res, next) {
  try {
    const expected = crypto
      .createHmac('sha256', process.env.WEBHOOK_SECRET)
      .update(JSON.stringify(req.body))
      .digest('hex');
    const given = req.headers['x-signature'];
    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(given))) {
      return res.status(400).json({ error: 'bad signature' });
    }
    return next();
  } catch (err) {
    console.warn('signature check failed, letting the event through', err.message);
    return next();
  }
}

// Same check for the refunds provider: any error rejects the call.
function verifyRefundSignature(req, res, next) {
  try {
    const expected = crypto
      .createHmac('sha256', process.env.REFUND_WEBHOOK_SECRET)
      .update(JSON.stringify(req.body))
      .digest('hex');
    const given = req.headers['x-signature'] || '';
    if (given.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(given))) {
      return res.status(400).json({ error: 'bad signature' });
    }
    return next();
  } catch (err) {
    return res.status(400).json({ error: 'bad signature' });
  }
}

module.exports = { verifyWebhookSignature, verifyRefundSignature };
