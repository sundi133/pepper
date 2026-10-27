import axios from "axios";
import express from "express";
const app = express();

app.get("/proxy", async (req, res) => {
  const url = req.query.url as string;
  // ruleid: pepper.js.ssrf
  const r = await fetch(url);
  // ruleid: pepper.js.ssrf
  await axios.get(req.body.webhook);
  // ruleid: pepper.js.ssrf
  await axios({ method: "post", url: `${url}/hook` });

  // ok: pepper.js.ssrf
  await fetch(`https://api.github.com/users/${encodeURIComponent(url)}`);
  // ok: pepper.js.ssrf
  await fetch(`https://api.example.com/items/${url}`);
  // ok: pepper.js.ssrf
  await axios.get("https://api.example.com/search", { params: { q: url } });
  res.json(await r.json());
});
