const Rijndael = require('rijndael-js');
const express = require("express");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 9000;

const key = process.env.KEY;
const iv = process.env.IV;

if (!key || !iv) {
    console.error("KEY and IV must be defined in the .env file");
    process.exit(1);
}

if (key.length !== 32 || iv.length !== 32) {
    console.error("Invalid KEY or IV length: KEY must be 32 bytes, and IV must be 32 bytes");
    process.exit(1);
}

const cipher = new Rijndael(key, 'cbc');

app.use(express.raw({ type: 'application/json' }));
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

app.get("/", (req, res) => {
    const { encryptedText } = req.query;

    if (!encryptedText) {
        return res.status(400).send('Missing body');
    }

    try {
        const buf = Buffer.from(encryptedText.toString(), 'base64');
        
        if (buf.length % 32 !== 0) {
            return res.status(400).send('Invalid encryptedText format');
        }

        const plaintextBuffer = Buffer.from(cipher.decrypt(buf, 256, iv));

        const plaintext = plaintextBuffer.toString();
        res.send(plaintext);
    } catch (error) {
        console.error("Decryption error:", error.message);
        res.status(500).send('Decryption failed');
    }
});