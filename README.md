# passwordmanager-remote-skeleton

This version of the password manager has a small Node/Express/SQLite
backend, allowing your password vault to be synced across multiple devices.

On the client side, `popup.js` calls functions from `api.js` to make requests to the remote server, which is implemented in `server/server.js.`

On the server side, credentials are served or updated based on the client's requests. Note that the server is SQLite and thus stores its data locally on your device. 

Currently, everything is implemented except the cryptography. Your job is to implement the four TODO functions in `crypto.js`: 

| Function | What it does |
|---|---|
| `deriveMasterKey` | Turns the master password into an AES-GCM key |
| `deriveLoginHash` | Derives the value sent to the server on log-in |
| `encryptRecord` | Encrypts one credential record |
| `decryptRecord` | Decrypts one credential record |

Do not change any other file.

## Running the server

1. `cd server && npm install && npm start` (listens on `http://localhost:3000`).
2. Note: all accounts and credentials will be stored locally, in `server/vault.db`. You can delete it to reset all accounts and credentials.

## Running the extension

Note that the server must be running for the extension to grant access to your vault.

1. Open Chrome and go to `chrome://extensions`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select this repo's root folder (the one
   containing `manifest.json`).
4. Open the extension from the toolbar to use it.
5. After editing any file, click the refresh icon on the extension's card in
   `chrome://extensions` to see your changes.


## A request from start to finish
Say you click "save password" in the extension:

- `popup.js` encrypts the password into a blob, using your master key, in the browser.
- `api.js` runs `createCredential(blob)`, which sends `POST /credentials` with the header `Authorization: Bearer <token>` and the body `{"blob": "..."}`.
- Express receives it. `express.json()` parses the body, then `requireAuth` checks the token and sets `req.userId`.
- The handler inserts the row and responds `{"id": 5, "version": 1}`.
- The extension stores that id and version for later edits.


## Checking your work

To manually check your work, you can simulate two devices by loading the extension in two different Chrome profiles, then logging into the same account from each:

1. Create an account, add a credential, and view it. This exercises all four
   functions.
2. To simulate two devices, load the extension in two different Chrome
   profiles. Each profile has its own storage, so data in the second profile
   has to come through the server. Log in on the second profile and check
   that your credentials appear.
3. Inspect what the server stores (for example, open `server/vault.db` with the
   `sqlite3` CLI). Can you find your password, your master key or any
   plaintext site name in it? You shouldn't.
