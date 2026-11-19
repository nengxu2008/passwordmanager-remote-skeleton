const enc = new TextEncoder()
const dec = new TextDecoder()

// The username is the PBKDF2 salt, so the usernames "Alice " and "alice" must give the same key.
export function normalizeUsername(username) {
    return username.trim().toLowerCase()
}

// TODO: derive the master key from the password.
//
// Input:   password (string), username (string)
// Output:  Promise<CryptoKey>, an AES-GCM 256-bit key usable for encrypt + decrypt
//
// Parameters:
//   - KDF:        PBKDF2 with SHA-256, 100,000 iterations
//   - Salt:       instead of a random salt, we use the normalized username
//   - Key type:   AES-GCM, 256 bits
//   - The key must be extractable (deriveLoginHash and exportKey both need
//     to read its raw bytes).
//
// Steps: import the password as raw PBKDF2 key material, then derive the key.
// WebCrypto calls: crypto.subtle.importKey, crypto.subtle.deriveKey
export async function deriveMasterKey(password, username) {
    throw new Error("TODO: implement deriveMasterKey")
}

// TODO: derive the value that is sent to the server on log-in attempt.
//
// Input:   masterKey (CryptoKey from deriveMasterKey), password (string)
// Output:  Promise<string>, 32 bytes, base64-encoded (use toBase64 below)
//
// Parameters:
//   - KDF:        PBKDF2 with SHA-256, only 1 iteration
//   - Key material: the RAW BYTES of the master key
//   - Salt:       the password (as bytes)
//   - Output:     256 bits
//
// Steps: export the master key's raw bytes, import them as PBKDF2 key
// material, then derive bits.
// WebCrypto calls: crypto.subtle.exportKey, crypto.subtle.importKey,
// crypto.subtle.deriveBits
export async function deriveLoginHash(masterKey, password) {
    throw new Error("TODO: implement deriveLoginHash")
}

// TODO: encrypt one credential record.
//
// Input:   masterKey (CryptoKey), record (object, e.g. {site, username, password})
// Output:  Promise<string>, one base64 string
//
// Format:
//   - Plaintext: JSON.stringify(record) as bytes. The site name is inside the
//     record, so it is encrypted too.
//   - Cipher:    AES-GCM, with a fresh random 12-byte IV for every call
//   - Output:    IV followed by ciphertext (the auth tag is already appended to
//     the ciphertext by WebCrypto), as one byte array, base64-encoded
//
// WebCrypto calls: crypto.getRandomValues, crypto.subtle.encrypt
export async function encryptRecord(masterKey, record) {
    throw new Error("TODO: implement encryptRecord")
}

// TODO: decrypt a blob produced by encryptRecord.
//
// Input:   masterKey (CryptoKey), blobBase64 (string)
// Output:  Promise<object>, the original record
//
// Steps: base64-decode (use fromBase64 below), split off the first 12 bytes
// as the IV, decrypt the rest, decode the bytes to a string, JSON.parse it.
// WebCrypto call: crypto.subtle.decrypt
export async function decryptRecord(masterKey, blobBase64) {
    throw new Error("TODO: implement decryptRecord")
}

// CryptoKey objects can't be stored directly, so they go through JWK.
export function exportKey(masterKey) {
    return crypto.subtle.exportKey("jwk", masterKey)
}

export function importKey(jwk) {
    return crypto.subtle.importKey("jwk", jwk, { name: "AES-GCM" }, true, ["encrypt", "decrypt"])
}

function toBase64(bytes) {
    return btoa(String.fromCharCode(...bytes))
}

function fromBase64(str) {
    return Uint8Array.from(atob(str), (c) => c.charCodeAt(0))
}
