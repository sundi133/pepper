const { exec } = require('child_process');
const cp = require('child_process');
function handler(req, res) {
  // ruleid: pepper.js.command-injection
  exec('echo ' + req.query.msg);
  // ruleid: pepper.js.command-injection
  cp.execSync(`convert ${req.body.file} out.png`);
  // ruleid: pepper.js.command-injection
  require('child_process').exec('ping ' + req.params.host);
  // ruleid: pepper.js.command-injection
  cp.spawn('ls ' + req.query.dir, [], { shell: true });
  // ok: pepper.js.command-injection
  cp.execFile('ping', ['-c', '1', req.params.host]);
  // ok: pepper.js.command-injection
  const m = /x(\d+)/.exec(req.query.q);
  // ok: pepper.js.command-injection
  exec('uptime');
  res.send(m);
}
