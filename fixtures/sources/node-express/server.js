const express = require("express");
const { exec } = require("child_process");

const app = express();

app.get("/search", (req, res) => {
  const q = req.query.q;
  exec("grep " + q + " ./data.txt", () => res.send("done"));
});

app.listen(3000);
