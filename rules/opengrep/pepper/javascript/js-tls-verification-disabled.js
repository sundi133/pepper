const https = require('https');
// ruleid: pepper.js.tls-verification-disabled
const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });
// ruleid: pepper.js.tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
// ok: pepper.js.tls-verification-disabled
const safe = new https.Agent({ rejectUnauthorized: true, ca: internalCa });
