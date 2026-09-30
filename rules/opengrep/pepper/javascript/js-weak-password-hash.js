const crypto = require('crypto');
// ruleid: pepper.js.weak-password-hash
const h1 = crypto.createHash('md5').update(req.body.password).digest('hex');
// ruleid: pepper.js.weak-password-hash
const h2 = crypto.createHash("sha1").update(userPwd).digest("hex");
// ok: pepper.js.weak-password-hash
const etag = crypto.createHash('md5').update(fileBuffer).digest('hex');
// ok: pepper.js.weak-password-hash
const h3 = crypto.createHash('sha256').update(password).digest('hex');
