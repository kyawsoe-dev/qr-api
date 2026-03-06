const express = require("express")
const mysql = require("mysql2/promise")
const QRCode = require("qrcode")
const jwt = require("jsonwebtoken")
const crypto = require("crypto")
const { v4: uuidv4 } = require("uuid")
const cors = require("cors")
require('dotenv').config()
const app = express()
app.use(express.json())
app.use(cors())

const QR_TOKEN_SECRET = process.env.QR_TOKEN_SECRET || "QR_TOKEN_SECRET"
const QR_KEY_SECRET = process.env.QR_KEY_SECRET || "QR_KEY_SECRET"

// DB config
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
})

async function testDBConnection() {
  try {
    const [rows] = await db.query('SELECT 1 AS result')
    console.log('Database connected successfully:', rows[0].result)
  } catch (err) {
    console.error('Database connection failed:', err)
    process.exit(1)
  }
}

testDBConnection()


const QR_SECRET_KEY = crypto
  .createHash("sha256")
  .update(QR_KEY_SECRET)
  .digest()

const ALGORITHM = "aes-256-cbc"

// Encrypt
function encrypt(text) {
  const iv = crypto.randomBytes(16)

  const cipher = crypto.createCipheriv(ALGORITHM, QR_SECRET_KEY, iv)

  let encrypted = cipher.update(text, "utf8", "hex")
  encrypted += cipher.final("hex")

  return iv.toString("hex") + ":" + encrypted
}

// Decrypt
function decrypt(text) {
  const parts = text.split(":")
  const iv = Buffer.from(parts.shift(), "hex")
  const encryptedText = parts.join(":")

  const decipher = crypto.createDecipheriv(ALGORITHM, QR_SECRET_KEY, iv)

  let decrypted = decipher.update(encryptedText, "hex", "utf8")
  decrypted += decipher.final("utf8")

  return decrypted
}

// Generate QR
app.get("/generate-qr/:userId", async (req, res) => {
  try {
    const userId = req.params.userId

    const [existingRows] = await db.query(
      "SELECT * FROM qr_tokens WHERE user_id=? AND used=0 AND expires_at > NOW()",
      [userId]
    )

    if (existingRows.length > 0) {
      const existingToken = existingRows[0].token

      console.log(encrypt(existingToken), "encoded token");
      
      const qr = await QRCode.toDataURL(encrypt(existingToken))
      return res.json({ qr })
    }

    const nonce = uuidv4()
    const token = jwt.sign({ userId, nonce }, QR_TOKEN_SECRET, { expiresIn: "10m" })
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000)

    await db.query(
      `INSERT INTO qr_tokens (user_id, token, nonce, expires_at, used) 
       VALUES (?, ?, ?, ?, 0)`,
      [userId, token, nonce, expiresAt]
    )

    const qrData = encrypt(token)

    console.log(qrData, "QR Data");
    
    const qr = await QRCode.toDataURL(qrData)

    res.json({ qr })
  } catch (err) {
    console.error(err)
    res.status(500).json({ message: "QR generation failed" })
  }
})

// Scan QR
app.post("/scan-qr", async (req, res) => {
  const { key: encodedToken, posId } = req.body

  if (!encodedToken) {
    return res.status(400).json({ message: "Token missing in request body" })
  }

  try {
    const token = decrypt(encodedToken)

    console.log(token, "TOKEN");
    
    const payload = jwt.verify(token, QR_TOKEN_SECRET)

    console.log(payload, "Payload");
    
    const userId = payload.userId
    const nonce = payload.nonce

    const [rows] = await db.query(
      "SELECT * FROM qr_tokens WHERE token=?",
      [token]
    )

    if (rows.length === 0)
      return res.status(400).json({ message: "Invalid QR" })

    const qr = rows[0]

    if (qr.status) return res.status(400).json({ message: "QR already used" })
    if (new Date(qr.expires_at) < new Date()) return res.status(400).json({ message: "QR expired" })
    if (nonce !== qr.nonce) return res.status(400).json({ message: "Nonce mismatch" })

    const [updateResult] = await db.query(
      "UPDATE qr_tokens SET used=1 WHERE id=? AND used=0",
      [qr.id]
    )

    if (updateResult.affectedRows === 0) {
      return res.status(400).json({ message: "QR already used" })
    }


    await db.query("UPDATE qr_tokens SET used=1 WHERE id=?", [qr.id])

    await db.query(
      `INSERT INTO qr_scan_logs (user_id, qr_token_id, pos_id, success) 
       VALUES (?, ?, ?, 1)`,
      [userId, qr.id, posId]
    )

    res.json({ success: true, userId })
  } catch (err) {
    console.error(err)
    res.status(400).json({ message: "Invalid or expired token" })
  }
})


app.listen(3000, () => {
  console.log("Server running on port 3000")
})