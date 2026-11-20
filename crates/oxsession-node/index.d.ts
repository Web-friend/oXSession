export interface CookiePair {
  name: string
  value: string
}

export interface CookieStats {
  pairs: number
  skipped: number
  truncated: boolean
  tooLong: boolean
}

export interface ParsedCookies {
  pairs: CookiePair[]
  stats: CookieStats
}

export interface ResolvedCredential {
  token: string
  source: 'bearer' | 'cookie'
}

export interface SessionRecord {
  /** Bearer credential. Do not log or expose it unnecessarily. */
  id: string
  subject: string
  issuedAt: number
  expiresAt: number
}

/** Parse a Cookie header with the core parser's limits and rules. */
export function parseCookies(header: string): ParsedCookies

/** Resolve a bearer or unique cookie credential. Defaults cookieName to "session". */
export function resolveCredential(
  authorization: string | null,
  cookieHeader: string,
  cookieName?: string,
): ResolvedCredential

/** HMAC signer whose keys are 32-byte unpadded base64url strings. */
export class CookieSigner {
  constructor(keyId: string, keyBase64url: string)
  readonly keyId: string
  addPrevious(keyId: string, keyBase64url: string): void
  rotate(keyId: string, keyBase64url: string): void
  sign(name: string, payload: string): string
  verify(name: string, wire: string): string
}

/** Process-local session manager; data is lost when the process exits. */
export class SessionManager {
  constructor(ttlSeconds?: number, absoluteTtlSeconds?: number)
  create(subject: string): Promise<SessionRecord>
  validate(id: string): Promise<SessionRecord>
  revoke(id: string): Promise<boolean>
  rotate(id: string): Promise<SessionRecord>
}

/** Stable categories appear on `.code` for errors thrown or rejected by this package. */
export type OxsessionErrorCode =
  | 'INVALID_INPUT'
  | 'MISSING_CREDENTIAL'
  | 'AMBIGUOUS_CREDENTIAL'
  | 'CONFIGURATION'
  | 'SIGNATURE_FAILURE'
  | 'INVALID_SUBJECT'
  | 'SUBJECT_TOO_LONG'
  | 'MISSING_SESSION'
  | 'EXPIRED_SESSION'
  | 'ENTROPY_FAILURE'
  | 'STORAGE_FAILURE'
