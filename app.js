const express = require("express")
const mysql = require("mysql2/promise")
const QRCode = require("qrcode")
const jwt = require("jsonwebtoken")
const { v4: uuidv4 } = require("uuid")
const cors = require("cors")

const app = express()
app.use(express.json())
app.use(cors())

const SECRET = process.env.QR_SECRET || "super_secret_key"

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
})

function encodeToken(token) {
  return Buffer.from(token).toString("base64url")
}

function decodeToken(encoded) {
  return Buffer.from(encoded, "base64url").toString("utf8")
}

app.get("/generate-qr/:userId", async (req, res) => {
  try {
    const userId = req.params.userId

    const [existingRows] = await db.query(
      "SELECT * FROM qr_tokens WHERE user_id=? AND used=0 AND expires_at > NOW()",
      [userId]
    )

    if (existingRows.length > 0) {
      const existingToken = existingRows[0].token

      console.log(encodeToken(existingToken), "encoded token");
      
      const qr = await QRCode.toDataURL(encodeToken(existingToken))
      return res.json({ qr })
    }

    const nonce = uuidv4()
    const token = jwt.sign({ userId, nonce }, SECRET, { expiresIn: "10m" })
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000)

    await db.query(
      `INSERT INTO qr_tokens (user_id, token, nonce, expires_at, used) 
       VALUES (?, ?, ?, ?, 0)`,
      [userId, token, nonce, expiresAt]
    )

    const qrData = encodeToken(token)
    const qr = await QRCode.toDataURL(qrData)

    res.json({ qr })
  } catch (err) {
    console.error(err)
    res.status(500).json({ message: "QR generation failed" })
  }
})

// Scan QR
app.post("/scan-qr", async (req, res) => {
  const { token: encodedToken, posId } = req.body

  if (!encodedToken) {
    return res.status(400).json({ message: "Token missing in request body" })
  }

  try {
    const token = decodeToken(encodedToken)

    const payload = jwt.verify(token, SECRET)
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