import Database from "better-sqlite3"

const db = new Database(new URL("./vault.db", import.meta.url).pathname)

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        login_hash TEXT NOT NULL      -- bcrypt of the client's loginHash, never the loginHash itself
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        blob TEXT NOT NULL,           -- encrypted site/username/password; opaque to the server
        version INTEGER NOT NULL
    );
`)

export default db
