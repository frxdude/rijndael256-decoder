const Rijndael = require('rijndael-js');
const express = require("express");
require("dotenv").config();

const app = express();
const key = process.env.KEY;
const iv = process.env.IV;

const cipher = new Rijndael(key, 'cbc');

app.listen(process.env.port || 9000,() => {
    console.log(`${process.env.port || 9000}`);
  })

app.get("/", (req, res) => {
    const { encryptedText } = req.query;
    const buf = Buffer.from(encryptedText, 'base64')
    const plaintext = Buffer.from(cipher.decrypt(buf, 256, iv));
    res.send(plaintext.toString());
});