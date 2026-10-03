import axios from 'axios'

// The simulator talks to the SAME backend the production console uses.
// baseURL is '' so requests hit the Django origin (/api/...).
const http = axios.create({ baseURL: '' })

let TOKEN = ''
let ROLE = ''

export function setAuth(token, role) {
  TOKEN = token
  ROLE = role
}

// Map a demo role to the credentials the backend accepts (see backend/auth.py).
export const DEMO_ACCOUNTS = {
  admin: { username: 'admin', password: 'admin', role: 'admin' },
  ops: { username: 'ops', password: 'ops', role: 'operator' },
  audit: { username: 'audit', password: 'audit', role: 'auditor' },
  viewer: { username: 'viewer', password: 'viewer', role: 'read_only' },
}

export async function login(role) {
  const acct = DEMO_ACCOUNTS[role]
  if (!acct) throw new Error('unknown role ' + role)
  const { data } = await http.post('/api/auth/login', {
    username: acct.username,
    password: acct.password,
  })
  setAuth(data.access_token, data.role)
  return data
}

function authHeaders() {
  const h = {}
  if (TOKEN) h['Authorization'] = `Bearer ${TOKEN}`
  return h
}

/**
 * Execute a single endpoint call as defined by the catalog entry `ep`.
 * `vars` is a map of scenario variables (subject_user_id, network, ids...).
 * Returns { status, ok, data, error, url }.
 */
export async function callEndpoint(ep, vars = {}, bodyOverride = null) {
  let url = ep.path
  // interpolate {param} placeholders in path
  for (const [k, v] of Object.entries(vars)) {
    if (v != null) url = url.replace(`{${k}}`, encodeURIComponent(v))
  }
  let body = null
  if (ep.body && bodyOverride == null) {
    body = JSON.parse(renderTemplate(JSON.stringify(ep.body), vars))
  } else if (bodyOverride != null) {
    body = bodyOverride
  }
  const cfg = { headers: authHeaders() }
  if (ep.params) {
    const params = {}
    for (const [k, v] of Object.entries(ep.params)) {
      const val = renderTemplate(String(v), vars)
      if (val) params[k] = val
    }
    if (Object.keys(params).length) cfg.params = params
  }
  try {
    const method = (ep.method || 'GET').toLowerCase()
    const res = await http.request({ method, url, data: body, ...cfg })
    return { status: res.status, ok: true, data: res.data, url, body }
  } catch (e) {
    return {
      status: e.response?.status || 0,
      ok: false,
      data: e.response?.data || { detail: e.message },
      url,
      body,
      error: e.message,
    }
  }
}

function renderTemplate(str, vars) {
  return str.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (_, key) => {
    const val = vars[key]
    return val == null ? '' : String(val)
  })
}

export { http }