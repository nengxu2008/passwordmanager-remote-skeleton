import crypto from "node:crypto"
import express from "express"
import bcrypt from "bcryptjs"
import db from "./db.js"

const app = express()    // app is your server
app.use(express.json())   // this one reads a request's JSON body and puts it in req.body
// No CORS middleware: extension pages that have host_permissions for this
// origin can call it without the server sending CORS headers.

function normalizeUsername(username) {
    return String(username).trim().toLowerCase()
}

function createSession(userId) {
    const token = crypto.randomBytes(32).toString("hex")
    db.prepare("INSERT INTO sessions (token, user_id) VALUES (?, ?)").run(token, userId)
    return token
}

function requireAuth(req, res, next) {
    const token = (req.headers.authorization || "").replace("Bearer ", "")
    const session = db.prepare("SELECT user_id FROM sessions WHERE token = ?").get(token)
    if (!session) return res.status(401).json({ error: "Not logged in" })
    req.userId = session.user_id
    req.token = token
    next()
}

app.post("/signup", async (req, res) => {
    const username = normalizeUsername(req.body.username)
    // loginHash is already a hash of the master key, but we hash it again so a
    // stolen database doesn't contain values that can be used to log in directly.
    const stored = await bcrypt.hash(req.body.loginHash, 10)
    try {
        const { lastInsertRowid } = db
            .prepare("INSERT INTO users (username, login_hash) VALUES (?, ?)")
            .run(username, stored)
        res.json({ token: createSession(lastInsertRowid) })
    } catch {
        // Tells the caller the username exists; unavoidable at signup.
        res.status(409).json({ error: "Username taken" })
    }
})

app.post("/login", async (req, res) => {
    const user = db
        .prepare("SELECT id, login_hash FROM users WHERE username = ?")
        .get(normalizeUsername(req.body.username))
    // Same response for unknown user and wrong password, so login doesn't reveal which usernames exist.
    if (!user || !(await bcrypt.compare(req.body.loginHash, user.login_hash))) {
        return res.status(401).json({ error: "Invalid username or password" })
    }
    res.json({ token: createSession(user.id) })
})

app.post("/logout", requireAuth, (req, res) => {
    db.prepare("DELETE FROM sessions WHERE token = ?").run(req.token)
    res.sendStatus(204)
})

app.get("/credentials", requireAuth, (req, res) => {
    res.json(db.prepare("SELECT id, blob, version FROM credentials WHERE user_id = ?").all(req.userId))
})

app.post("/credentials", requireAuth, (req, res) => {
    const { lastInsertRowid } = db
        .prepare("INSERT INTO credentials (user_id, blob, version) VALUES (?, ?, 1)")
        .run(req.userId, req.body.blob)
    res.json({ id: Number(lastInsertRowid), version: 1 })
})

// For PUT and DELETE, matching on id AND user_id AND version means a stale
// version and a row that no longer exists both change 0 rows -> the same 409.
app.put("/credentials/:id", requireAuth, (req, res) => {
    const { changes } = db
        .prepare("UPDATE credentials SET blob = ?, version = version + 1 WHERE id = ? AND user_id = ? AND version = ?")
        .run(req.body.blob, req.params.id, req.userId, req.body.version)
    if (changes === 0) return res.status(409).json({ error: "Conflict" })
    res.json({ version: req.body.version + 1 })
})

app.delete("/credentials/:id", requireAuth, (req, res) => {
    const { changes } = db
        .prepare("DELETE FROM credentials WHERE id = ? AND user_id = ? AND version = ?")
        .run(req.params.id, req.userId, req.query.version)
    if (changes === 0) return res.status(409).json({ error: "Conflict" })
    res.sendStatus(204)
})

app.listen(3000, () => console.log("Server listening on http://localhost:3000"))
