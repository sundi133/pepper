import express from "express";
const app = express();

app.get("/orders/:id", async (req, res) => {
  const id = req.params.id;
  // ruleid: pepper.js.sql-injection
  await pool.query(`SELECT * FROM orders WHERE id = ${id}`);
  // ruleid: pepper.js.sql-injection
  await db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'");
  // ruleid: pepper.js.sql-injection
  await prisma.$queryRawUnsafe("SELECT * FROM t WHERE x = " + req.body.x);
  // ruleid: pepper.js.sql-injection
  await knex.raw(`DELETE FROM t WHERE owner = '${req.headers["x-user"]}'`);

  // ok: pepper.js.sql-injection
  await pool.query("SELECT * FROM orders WHERE id = $1", [id]);
  // ok: pepper.js.sql-injection
  await db.query("SELECT * FROM orders WHERE id = " + parseInt(req.params.id, 10));
  // ok: pepper.js.sql-injection
  await db.query("SELECT * FROM users WHERE name = " + mysql.escape(req.query.name));
  // ok: pepper.js.sql-injection
  const m = /(\d+)/.exec(req.query.q);
  // ok: pepper.js.sql-injection
  await pool.query(`SELECT * FROM orders WHERE status = 'open'`);
  res.json(m);
});
