'use strict'

const native = require('./oxsession.node')

function normalizeError(error) {
  const match = /^OXSESSION_([A-Z_]+):\s*(.*)$/.exec(error.message || '')
  if (!match) return error
  error.code = match[1]
  error.message = match[2]
  return error
}

function wrapSync(fn) {
  return (...args) => {
    try {
      return fn(...args)
    } catch (error) {
      throw normalizeError(error)
    }
  }
}

function wrapAsync(fn) {
  return async (...args) => {
    try {
      return await fn(...args)
    } catch (error) {
      throw normalizeError(error)
    }
  }
}

class CookieSigner {
  constructor(keyId, keyBase64url) {
    try {
      this.inner = new native.CookieSigner(keyId, keyBase64url)
    } catch (error) {
      throw normalizeError(error)
    }
  }

  get keyId() { return this.inner.keyId }

  addPrevious(keyId, keyBase64url) {
    return wrapSync(this.inner.addPrevious.bind(this.inner))(keyId, keyBase64url)
  }

  rotate(keyId, keyBase64url) {
    return wrapSync(this.inner.rotate.bind(this.inner))(keyId, keyBase64url)
  }

  sign(name, payload) {
    return wrapSync(this.inner.sign.bind(this.inner))(name, payload)
  }

  verify(name, wire) {
    return wrapSync(this.inner.verify.bind(this.inner))(name, wire)
  }
}

class SessionManager {
  constructor(ttlSeconds, absoluteTtlSeconds) {
    try {
      this.inner = new native.SessionManager(ttlSeconds, absoluteTtlSeconds)
    } catch (error) {
      throw normalizeError(error)
    }
  }

  create(subject) { return wrapAsync(this.inner.create.bind(this.inner))(subject) }
  validate(id) { return wrapAsync(this.inner.validate.bind(this.inner))(id) }
  revoke(id) { return wrapAsync(this.inner.revoke.bind(this.inner))(id) }
  rotate(id) { return wrapAsync(this.inner.rotate.bind(this.inner))(id) }
}

module.exports = {
  CookieSigner,
  SessionManager,
  parseCookies: wrapSync(native.parseCookies),
  resolveCredential: (authorization, cookieHeader, cookieName = 'session') =>
    wrapSync(native.resolveCredential)(authorization, cookieHeader, cookieName),
}
