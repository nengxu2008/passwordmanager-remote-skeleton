import * as api from "./api.js"
import { normalizeUsername, deriveMasterKey, deriveLoginHash, encryptRecord, decryptRecord, exportKey, importKey } from "./crypto.js"

const app = document.getElementById("app")

// Lives only as long as the popup is open; a copy is kept in chrome.storage.session
// so reopening the popup doesn't ask for the master password again.
let masterKey = null

document.addEventListener("DOMContentLoaded", async () => {
    const { token, masterKeyJwk } = await chrome.storage.session.get(["token", "masterKeyJwk"])
    if (token && masterKeyJwk) {
        masterKey = await importKey(masterKeyJwk)
        showHomeScreen()
    } else {
        showLoginScreen()
    }
})

function setMessage(text) {
    document.getElementById("message").textContent = text
}

// Shared error handling for every API call.
async function handleError(err) {
    if (err instanceof api.SessionExpiredError) {
        await chrome.storage.session.clear()
        showLoginScreen()
    } else if (err instanceof api.ConflictError) {
        setMessage("Error: This credential was changed on another device. Refresh and try again.")
    } else {
        setMessage(err.message)
    }
}

function showLoginScreen() {
    app.innerHTML = `
    <h2>Welcome Back</h2>
    <input type="text" id="username" placeholder="Username" />
    <input type="password" id="masterPassword" placeholder="Master Password" />
    <button id="loginBtn">Unlock</button>
    <button id="toSignup">Create account</button>
    <p id="message"></p>
  `
    document.getElementById("loginBtn").addEventListener("click", handleLogin)
    document.getElementById("toSignup").addEventListener("click", showSignupScreen)
}

function showSignupScreen() {
    app.innerHTML = `
    <h2>Create Account</h2>

    <p>Your master password must:</p>
    <ul>
        <li>Be 8-20 characters long</li>
        <li>Contain both uppercase and lowercase letters</li>
        <li>Contain at least one digit (0-9)</li>
        <li>Contain at least one symbol (non-alphanumeric)</li>
    </ul>

    <input type="text" id="username" placeholder="Username" />
    <input type="password" id="masterPassword" placeholder="Master Password" />
    <input type="password" id="confirmPassword" placeholder="Confirm Password" />
    <button id="signupBtn">Create Account</button>
    <button id="toLogin">I already have an account</button>
    <p id="message"></p>
  `
    document.getElementById("signupBtn").addEventListener("click", handleSignup)
    document.getElementById("toLogin").addEventListener("click", showLoginScreen)
}

function showHomeScreen() {
    app.innerHTML = `
    <button id="viewSavedCreds">View Saved Credentials</button>
    <button id="logoutBtn">Log out</button>
    <hr>
    <input type="text" id="accountName" placeholder="Site Name" />
    <input type="text" id="username" placeholder="Site Username" />
    <input type="password" id="password" placeholder="Site Password" />
    <button id="addCredBtn">Save Credentials</button>
    <p id="message"></p> `
    document.getElementById("addCredBtn").addEventListener("click", addCredentials)
    document.getElementById("viewSavedCreds").addEventListener("click", viewSavedCredentials)
    document.getElementById("logoutBtn").addEventListener("click", handleLogout)
}

function validateMasterPassword(password) {
    if (password.length < 8 || password.length > 20) {
        return "Password must be 8-20 characters long."
    }
    if (!/[a-z]/.test(password)) {
        return "Password must contain at least one lowercase letter."
    }
    if (!/[A-Z]/.test(password)) {
        return "Password must contain at least one uppercase letter."
    }
    if (!/[0-9]/.test(password)) {
        return "Password must contain at least one digit."
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
        return "Password must contain at least one symbol (non-alphanumeric)."
    }
    return null
}

// Signup and login do the same client-side work and differ only in which endpoint receives the loginHash.
async function authenticate(apiCall, username, masterPassword) {
    masterKey = await deriveMasterKey(masterPassword, username)
    const loginHash = await deriveLoginHash(masterKey, masterPassword)
    const { token } = await apiCall(normalizeUsername(username), loginHash)
    await chrome.storage.session.set({ token, masterKeyJwk: await exportKey(masterKey) })
    showHomeScreen()
}

async function handleSignup() {
    const username = document.getElementById("username").value
    const masterPassword = document.getElementById("masterPassword").value
    const confirmPassword = document.getElementById("confirmPassword").value

    if (!username.trim() || !masterPassword) {
        setMessage("Please fill in all fields")
        return
    }

    if (masterPassword !== confirmPassword) {
        setMessage("Passwords don't match")
        return
    }

    const passwordError = validateMasterPassword(masterPassword)
    if (passwordError) {
        setMessage(passwordError + " Please try again.")
        document.getElementById("masterPassword").value = ""
        document.getElementById("confirmPassword").value = ""
        return
    }

    try {
        await authenticate(api.signup, username, masterPassword)
    } catch (err) {
        handleError(err)
    }
}

async function handleLogin() {
    const username = document.getElementById("username").value
    const masterPassword = document.getElementById("masterPassword").value

    if (!username.trim() || !masterPassword) {
        setMessage("Please fill in all fields")
        return
    }

    try {
        await authenticate(api.login, username, masterPassword)
    } catch (err) {
        handleError(err)
    }
}

async function handleLogout() {
    try {
        await api.logout()
    } catch {
        // Even if the server can't be reached, we still drop the local session below.
    }
    await chrome.storage.session.clear()
    masterKey = null
    showLoginScreen()
}

async function addCredentials() {
    const site = document.getElementById("accountName").value
    const username = document.getElementById("username").value
    const password = document.getElementById("password").value

    if (!site || !username || !password) {
        setMessage("Please fill in all fields")
        return
    }

    try {
        await api.createCredential(await encryptRecord(masterKey, { site, username, password }))
        setMessage("Credentials saved!")
        document.getElementById("accountName").value = ""
        document.getElementById("username").value = ""
        document.getElementById("password").value = ""
    } catch (err) {
        handleError(err)
    }
}

// Fetches the whole vault fresh from the server each time and decrypts it here.
async function viewSavedCredentials() {
    app.innerHTML = `
    <h3>All Saved Credentials</h3>
    <div id="credList"></div>
    <p id="message"></p>
    <button id="back">Back</button>
  `
    document.getElementById("back").addEventListener("click", showHomeScreen)

    const credList = document.getElementById("credList")

    try {
        const vault = await api.fetchVault()

        if (vault.length === 0) {
            credList.textContent = "No saved credentials"
            return
        }

        for (const item of vault) {
            const record = await decryptRecord(masterKey, item.blob)
            credList.appendChild(formatCredential(item, record))
        }
    } catch (err) {
        handleError(err)
    }
}

// item is {id, blob, version} from the server; record is the decrypted {site, username, password}.
function formatCredential(item, record) {
    const cred = document.createElement("div")

    const accountDiv = document.createElement("b")
    accountDiv.textContent = record.site
    cred.appendChild(accountDiv)

    const usernameDiv = document.createElement("div")
    usernameDiv.textContent = "Username: " + record.username
    cred.appendChild(usernameDiv)

    const passwordDiv = document.createElement("div")
    passwordDiv.textContent = "Password: " + "*".repeat(record.password.length)

    const showButton = document.createElement("button")
    showButton.textContent = "Show"
    let show = false
    showButton.addEventListener("click", () => {
        show = !show
        passwordDiv.textContent = show ? "Password: " + record.password : "Password: " + "*".repeat(record.password.length)
        showButton.textContent = show ? "Hide" : "Show"
    })

    const passwordRow = document.createElement("div")
    passwordRow.append(passwordDiv, " ", showButton)
    cred.appendChild(passwordRow)

    const editButton = document.createElement("button")
    editButton.textContent = "Edit"
    editButton.addEventListener("click", () => cred.replaceWith(formatEditForm(item, record)))

    const deleteButton = document.createElement("button")
    deleteButton.textContent = "Delete"
    deleteButton.addEventListener("click", async () => {
        try {
            await api.deleteCredential(item.id, item.version)
            viewSavedCredentials()
        } catch (err) {
            handleError(err)
        }
    })

    cred.append(editButton, " ", deleteButton, document.createElement("hr"))

    return cred
}

function formatEditForm(item, record) {
    const form = document.createElement("div")

    const site = document.createElement("input")
    site.value = record.site
    const username = document.createElement("input")
    username.value = record.username
    const password = document.createElement("input")
    password.value = record.password

    const save = document.createElement("button")
    save.textContent = "Save"
    save.addEventListener("click", async () => {
        if (!site.value || !username.value || !password.value) {
            setMessage("Please fill in all fields")
            return
        }
        try {
            // Send the version we last saw; the server rejects it if someone else changed the row since.
            const blob = await encryptRecord(masterKey, { site: site.value, username: username.value, password: password.value })
            await api.updateCredential(item.id, blob, item.version)
            viewSavedCredentials()
        } catch (err) {
            handleError(err)
        }
    })

    const cancel = document.createElement("button")
    cancel.textContent = "Cancel"
    cancel.addEventListener("click", viewSavedCredentials)

    form.append(site, username, password, save, " ", cancel, document.createElement("hr"))
    return form
}
