const { Queue, Worker } = require('bullmq');
const { Invoice } = require('../services/db');
const { renderPdf, mail } = require('../services/mailer');

const exportQueue = new Queue('invoice-export');

new Worker('invoice-export', async (job) => {
  if (job.name === 'export') {
    const invoice = await Invoice.findByPk(job.data.invoiceId);
    await mail(job.data.email, 'Your invoice', await renderPdf(invoice));
  }
  if (job.name === 'send') {
    const invoice = await Invoice.findOne({ where: { id: job.data.invoiceId, ownerId: job.data.ownerId } });
    if (!invoice) return;
    await mail(invoice.customerEmail, 'Invoice', await renderPdf(invoice));
  }
});

module.exports = { exportQueue };
