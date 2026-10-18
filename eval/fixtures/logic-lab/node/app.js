// Evaluation fixture (eval/truth/logic-lab.json): an invoicing service with
// labelled authorization and logic flaws next to safe twins. Not a real app.
const express = require('express');

const app = express();
app.use(express.json());

app.use('/api', require('./routes/invoices'));
app.use('/api', require('./routes/admin'));
app.use('/api', require('./routes/reports'));
app.use('/api', require('./routes/orders'));
app.use('/api', require('./routes/webhooks'));
app.use('/api', require('./routes/wallet'));
app.use('/api', require('./routes/checkout'));

app.get('/health', (req, res) => res.json({ ok: true }));

module.exports = app;
