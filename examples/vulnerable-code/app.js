// Intentionally vulnerable. For testing ClayScan locally only. Do not deploy.

import express from 'express';
import { execSync } from 'child_process';
import crypto from 'crypto';
import mysql from 'mysql';

const app = express();
const API_KEY = "EXAMPLE_fake_hardcoded_key_not_real_1234";

app.get('/ping', (req, res) => {
  const out = execSync('ping -c 1 ' + req.query.host);
  res.send(out);
});

app.get('/user', (req, res) => {
  const db = mysql.createConnection({});
  db.query(`SELECT * FROM users WHERE id = ${req.query.id}`, (e, rows) => res.json(rows));
});

app.get('/render', (req, res) => {
  const html = `<div>${req.query.name}</div>`;
  res.send(`<script>document.write(location.hash)</script>${html}`);
});

app.get('/go', (req, res) => res.redirect(req.query.url));

function makeToken() {
  return 'tok_' + Math.random().toString(36);
}

const hash = crypto.createHash('md5').update('pw').digest('hex');

const client = { rejectUnauthorized: false };

eval(process.argv[2]);

export { app, makeToken, hash, client, API_KEY };
