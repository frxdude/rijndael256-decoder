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
    const { text, encrypt } = req.query;

    if (!text)
        return res.status(400).send('Missing param');

    try {
        if (encrypt === 'true') {
            const plaintextBuffer = Buffer.from(text, 'utf8');
            const encryptedBuffer = cipher.encrypt(plaintextBuffer, 256, iv);
            return res.send(Buffer.from(encryptedBuffer).toString('base64'));
        }

        const encryptedBuffer = Buffer.from(text, 'base64');
        if (encryptedBuffer.length % 32 !== 0)
            return res.status(400).send('Invalid text format');
        const decryptedBuffer = Buffer.from(cipher.decrypt(encryptedBuffer, 256, iv));
        return res.send(decryptedBuffer.toString('utf8')); 
    } catch (error) {
        console.error("Encryption/Decryption error:", error.message);
        res.status(500).send('Operation failed');
    }
});