import https from 'node:https';
import http from 'node:http';
import { URL } from 'node:url';
import { config, usingApiKey } from './config.js';

/**
 * OPNsense API client.
 *
 * Two auth modes, because the two feeds we need have different requirements:
 *
 *   - API key/secret  -> HTTP Basic. Bypasses CSRF entirely, so the POST-only
 *                        IDS alert endpoint works, and nothing expires.
 *   - session          -> scrapes the login form, holds PHPSESSID, and pulls the
 *                        X-CSRFToken value out of the page HTML so POSTs are
 *                        accepted. Used only when no API key is configured.
 *
 * Verified against OPNsense 26.7.1_1:
 *   GET  /api/diagnostics/firewall/log?limit=N&digest=D  -> array, newest first
 *   POST /api/ids/service/queryAlerts                    -> {rows, total, ...}
 */
export class OPNsenseClient {
  constructor(opts = {}) {
    const c = { ...config.opnsense, ...opts };
    this.base = new URL(c.url);
    this.key = c.key;
    this.secret = c.secret;
    this.user = c.user;
    this.pass = c.pass;
    this.useApiKey = Boolean(this.key && this.secret);

    const isTls = this.base.protocol === 'https:';
    this.transport = isTls ? https : http;
    this.agent = isTls
      ? new https.Agent({ keepAlive: true, maxSockets: 4, rejectUnauthorized: !c.tlsInsecure })
      : new http.Agent({ keepAlive: true, maxSockets: 4 });

    this.cookies = new Map();
    this.csrfToken = null;
    this.loginPromise = null;
  }

  get authMode() {
    return this.useApiKey ? 'apikey' : 'session';
  }

  #cookieHeader() {
    if (!this.cookies.size) return null;
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  #storeCookies(setCookie) {
    for (const raw of setCookie || []) {
      const [pair] = raw.split(';');
      const eq = pair.indexOf('=');
      if (eq > 0) this.cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }

  #request(method, pathname, { body, contentType, headers = {}, timeout = 60000 } = {}) {
    const url = new URL(pathname, this.base);
    const hdrs = { Accept: 'application/json', ...headers };

    if (this.useApiKey) {
      hdrs.Authorization = 'Basic ' + Buffer.from(`${this.key}:${this.secret}`).toString('base64');
    } else {
      const cookie = this.#cookieHeader();
      if (cookie) hdrs.Cookie = cookie;
      if (this.csrfToken && method !== 'GET') hdrs['X-CSRFToken'] = this.csrfToken;
    }

    let payload = null;
    if (body !== undefined && body !== null) {
      payload = typeof body === 'string' ? body : JSON.stringify(body);
      hdrs['Content-Type'] = contentType || 'application/json';
      hdrs['Content-Length'] = Buffer.byteLength(payload);
    }

    return new Promise((resolve, reject) => {
      const req = this.transport.request(
        {
          protocol: url.protocol,
          hostname: url.hostname,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: url.pathname + url.search,
          method,
          headers: hdrs,
          agent: this.agent,
        },
        (res) => {
          this.#storeCookies(res.headers['set-cookie']);
          const chunks = [];
          res.on('data', (d) => chunks.push(d));
          res.on('end', () =>
            resolve({
              status: res.statusCode,
              headers: res.headers,
              body: Buffer.concat(chunks).toString('utf8'),
            })
          );
        }
      );
      req.setTimeout(timeout, () => req.destroy(new Error(`timeout after ${timeout}ms: ${method} ${pathname}`)));
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  // The CSRF token is emitted inline in every page as a jQuery ajaxSetup header.
  static #extractCsrf(html) {
    return /X-CSRFToken",\s*"([^"]+)"/.exec(html)?.[1] ?? null;
  }

  // Hidden login inputs use a randomised field name per session, so they are
  // collected generically rather than looked up by a fixed name.
  static #extractHiddenInputs(html) {
    const out = {};
    const re = /<input type="hidden" name="([^"]+)" value="([^"]*)"/g;
    let m;
    while ((m = re.exec(html))) out[m[1]] = m[2];
    return out;
  }

  async login() {
    if (this.useApiKey) return;
    if (this.loginPromise) return this.loginPromise;

    this.loginPromise = (async () => {
      this.cookies.clear();
      this.csrfToken = null;

      const page = await this.#request('GET', '/');
      if (page.status !== 200) throw new Error(`login page returned HTTP ${page.status}`);

      const form = OPNsenseClient.#extractHiddenInputs(page.body);
      const params = new URLSearchParams(form);
      params.set('usernamefld', this.user);
      params.set('passwordfld', this.pass);
      params.set('login', '1');

      const res = await this.#request('POST', '/', {
        body: params.toString(),
        contentType: 'application/x-www-form-urlencoded',
      });
      if (res.status !== 200) throw new Error(`login POST returned HTTP ${res.status}`);
      if (/id="passwordfld"/.test(res.body)) {
        throw new Error(`login failed for user "${this.user}" - still on the login page`);
      }

      this.csrfToken = OPNsenseClient.#extractCsrf(res.body);
      if (!this.csrfToken) throw new Error('logged in but could not extract an X-CSRFToken');
    })().finally(() => {
      this.loginPromise = null;
    });

    return this.loginPromise;
  }

  async #api(method, pathname, opts = {}) {
    if (!this.useApiKey && !this.csrfToken) await this.login();

    let res = await this.#request(method, pathname, opts);

    // A session can expire underneath us; an API key cannot, so only retry once
    // and only in session mode.
    if (!this.useApiKey && (res.status === 401 || res.status === 403 || /id="passwordfld"/.test(res.body))) {
      await this.login();
      res = await this.#request(method, pathname, opts);
    }

    if (res.status !== 200) {
      throw new Error(`${method} ${pathname} -> HTTP ${res.status}: ${res.body.slice(0, 200)}`);
    }
    try {
      return JSON.parse(res.body);
    } catch {
      throw new Error(`${method} ${pathname} returned non-JSON: ${res.body.slice(0, 200)}`);
    }
  }

  /**
   * Firewall log, newest first. Raw passthrough.
   *
   * The `digest` filter is INCLUSIVE: passing the `__digest__` of a row returns
   * everything from that row onward, that row included. Verified on 26.7.1_1.
   * Prefer fwLogSince(), which strips it.
   */
  async fwLog({ limit = config.poll.fwLimit, digest = null } = {}) {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (digest) qs.set('digest', digest);
    const rows = await this.#api('GET', `/api/diagnostics/firewall/log?${qs}`);
    return Array.isArray(rows) ? rows : [];
  }

  /**
   * Strictly-newer-than-`digest` firewall rows, newest first.
   *
   * Returns { rows, digest, saturated }. `saturated` means the fetch came back
   * full, so events older than the window may have been missed - the caller
   * should resync rather than pretend the delta is complete.
   */
  async fwLogSince(digest, { limit = config.poll.fwLimit } = {}) {
    const rows = await this.fwLog({ limit, digest });
    const saturated = digest != null && rows.length >= limit;
    const fresh = digest == null ? rows : rows.filter((r) => r.__digest__ !== digest);
    return { rows: fresh, digest: rows[0]?.__digest__ ?? digest, saturated };
  }

  /**
   * One page of the raw filter log, newest first. POST-only.
   *
   * This is the pageable counterpart to fwLog(), and the only way to read more
   * than a few hours back. fwLog() has no cursor, so reaching a day of history
   * through it means a single enormous request - and at 400k rows that exhausts
   * PHP's 1 GB limit and the request dies on the firewall. Here each page costs
   * ~3 MB regardless of depth, and the log retains around 72 hours.
   *
   * Rows are raw syslog: use parseFilterLine() from ./filterlog.js on `line`.
   * `rowCount` is capped server-side at 9999.
   */
  async filterLogPage({ page = 1, rowCount = 10000 } = {}) {
    const res = await this.#api('POST', '/api/diagnostics/log/core/filter', {
      body: { current: page, rowCount },
    });
    const rows = res?.rows ?? [];
    // Other daemons share this log; only filterlog rows are parseable.
    return rows.filter((r) => r.process_name === 'filterlog');
  }

  /** Suricata alerts from eve.json, newest first. POST-only. */
  async idsAlerts({ rowCount = config.poll.idsRowCount, current = 1, searchPhrase = '' } = {}) {
    const res = await this.#api('POST', '/api/ids/service/queryAlerts', {
      body: { current, rowCount, searchPhrase },
    });
    return { rows: res?.rows ?? [], total: res?.total ?? 0 };
  }

  async idsStatus() {
    return this.#api('GET', '/api/ids/service/status');
  }

  async interfaceNames() {
    return this.#api('GET', '/api/diagnostics/interface/getInterfaceNames');
  }

  /** Public WAN address, used to anchor "home" on the map when no lat/lon is set. */
  async wanAddress() {
    const ifaces = await this.#api('GET', '/api/diagnostics/interface/getInterfaceConfig');
    for (const [name, cfg] of Object.entries(ifaces || {})) {
      if (/^pppoe|^pppoa/.test(name) && cfg?.ipv4?.[0]?.ipaddr) return cfg.ipv4[0].ipaddr;
    }
    for (const cfg of Object.values(ifaces || {})) {
      const ip = cfg?.ipv4?.[0]?.ipaddr;
      if (ip && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip)) return ip;
    }
    return null;
  }
}

export const defaultClient = () => new OPNsenseClient();
export { usingApiKey };
