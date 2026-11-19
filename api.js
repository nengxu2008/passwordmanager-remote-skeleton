const API = "http://localhost:3000"

export class SessionExpiredError extends Error {}
export class ConflictError extends Error {}

async function request(method, path, body) {
    const { token } = await chrome.storage.session.get("token")
    const res = await fetch(API + path, {
        method,
        headers: {
            "Content-Type": "application/json",
            ...(token && { Authorization: "Bearer " + token }),
        },
        body: body && JSON.stringify(body),
    })
    if (res.status === 409) throw new ConflictError()
    if (!res.ok) {
        const { error } = await res.json().catch(() => ({}))
        // 401 on a credential call means our token is dead; on login it just means bad credentials.
        if (res.status === 401 && token) throw new SessionExpiredError()
        throw new Error(error || "Request failed")
    }
    return res.status === 204 ? null : res.json()
}

export const signup = (username, loginHash) => request("POST", "/signup", { username, loginHash })
export const login = (username, loginHash) => request("POST", "/login", { username, loginHash })
export const logout = () => request("POST", "/logout")
export const fetchVault = () => request("GET", "/credentials")
export const createCredential = (blob) => request("POST", "/credentials", { blob })
export const updateCredential = (id, blob, version) => request("PUT", `/credentials/${id}`, { blob, version })
export const deleteCredential = (id, version) => request("DELETE", `/credentials/${id}?version=${version}`)
