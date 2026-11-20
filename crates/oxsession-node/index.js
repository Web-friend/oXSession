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

class CookieSigner extends native.CookieSigner {
  constructor(keyId, keyBase64url) {
    try {
      super(keyId, keyBase64url)
    } catch (error) {
      throw normalizeError(error)
    }
  }

  addPrevious(keyId, keyBase64url) {
    return wrapSync(super.addPrevious.bind(this))(keyId, keyBase64url)
  }

  rotate(keyId, keyBase64url) {
    return wrapSync(super.rotate.bind(this))(keyId, keyBase64url)
  }

  sign(name, payload) {
    return wrapSync(super.sign.bind(this))(name, payload)
  }

  verify(name, wire) {
    return wrapSync(super.verify.bind(this))(name, wire)
  }
}

class SessionManager extends native.SessionManager {
  constructor(ttlSeconds, absoluteTtlSeconds) {
    try {
      super(ttlSeconds, absoluteTtlSeconds)
    } catch (error) {
      throw normalizeError(error)
    }
  }

  create(subject) { return wrapAsync(super.create.bind(this))(subject) }
  validate(id) { return wrapAsync(super.validate.bind(this))(id) }
  revoke(id) { return wrapAsync(super.revoke.bind(this))(id) }
  rotate(id) { return wrapAsync(super.rotate.bind(this))(id) }
}

module.exports = {
  CookieSigner,
  SessionManager,
  parseCookies: wrapSync(native.parseCookies),
  resolveCredential: (authorization, cookieHeader, cookieName = 'session') =>
    wrapSync(native.resolveCredential)(authorization, cookieHeader, cookieName),
}
