//! `oxsession-devtool` — a local, redaction-first inspector for oXSession.
//!
//! The tool is deliberately read-only when it comes to sessions: it never
//! mints, validates against a store, rotates, or revokes. It parses headers,
//! resolves credentials, verifies signed values with keys you provide, and
//! checks id/policy shape. Credential-bearing values are redacted unless the
//! caller explicitly asks to reveal them.
//!
//! Exit codes:
//!
//! - `0` — success / the answer is positive (`valid: true`).
//! - `1` — the answer is negative (`valid: false`, missing credential, bad MAC).
//! - `2` — usage error.
//! - `3` — configuration/IO failure (for example, a bad key encoding).

#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::process::ExitCode;

use oxsession_core::{
    ErrorCategory, MAX_COOKIE_HEADER_BYTES, MAX_COOKIE_PAIRS, MAX_SESSION_ID_BYTES,
    MIN_SESSION_ID_BYTES, Pairs, Prefix, SessionId, is_valid_name, resolve,
};
use oxsession_session::Policy;
use oxsession_sign::{CookieSigner, ErrorCategory as SignCategory, KeyId, SecretKey};
use serde_json::{Value, json};

const USAGE: &str = "\
oxsession-devtool — inspect cookies, credentials, signatures, and session ids

USAGE:
  oxsession-devtool <command> [options]

COMMANDS:
  parse-cookie        Parse a Cookie header and report pairs plus parser stats
  resolve-credential  Resolve Authorization/cookie precedence (redacted by default)
  check-cookie        Verify an os1 signed value with one or more keys
  inspect-id          Check a session id's shape and length (no store lookup)
  policy              Validate TTLs and an optional cookie-name configuration
  help                Print this text

COMMON:
  --help              Print this text

parse-cookie:
  --header <value>          Cookie header to parse (repeatable; joined with \"; \")
  --session-cookie <name>   Credential cookie name to redact (default: session)
  --redact <name>           Additional name to redact (repeatable)
  --reveal-name <name>      Reveal this name's value (repeatable; wins over redact)

resolve-credential:
  --authorization <value>   Raw Authorization header (optional)
  --cookie <value>          Cookie header (optional, default empty)
  --cookie-name <name>      Credential cookie name (default: session)
  --reveal                  Include the resolved token in the output

check-cookie:
  --name <name>             Cookie name the value was signed for (required)
  --value <wire>            The os1.<keyid>.<payload>.<mac> value (required)
  --key <keyid:base64url>   Signing key; first is current, rest verify (repeatable)
  --key-file <path>         File of keyid:base64url lines (0600 recommended)
  --reveal-payload          Include the verified payload in the output

inspect-id:
  --id <value>              Session id to inspect (required)

policy:
  --ttl <seconds>           Idle lifetime (required)
  --absolute <seconds>      Absolute lifetime (required)
  --cookie-name <name>      Optional cookie name to validate
  --secure                  Treat the deployment as HTTPS/Secure

EXAMPLES:
  oxsession-devtool parse-cookie --header 'theme=dark; session=abc'
  oxsession-devtool resolve-credential --authorization 'Bearer abc' --cookie 'session=abc'
  oxsession-devtool check-cookie --name session --value 'os1.k1.…' --key \"k1:$KEY\"
  oxsession-devtool inspect-id --id 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  oxsession-devtool policy --ttl 604800 --absolute 2592000 --cookie-name __Host-session --secure

Output is JSON on stdout. Diagnostics go to stderr.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(CliError::Usage(message)) => {
            eprintln!("error: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
        Err(CliError::Configuration(message)) => {
            eprintln!("error: {message}");
            ExitCode::from(3)
        }
    }
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    Configuration(String),
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }
}

#[derive(Default)]
struct Options {
    values: BTreeMap<String, Vec<String>>,
    switches: BTreeSet<String>,
}

impl Options {
    fn first(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.values.get(name).cloned().unwrap_or_default()
    }

    fn has(&self, name: &str) -> bool {
        self.switches.contains(name)
    }

    fn require(&self, name: &str) -> Result<&str, CliError> {
        self.first(name)
            .ok_or_else(|| CliError::usage(format!("--{name} is required")))
    }

    fn u64(&self, name: &str) -> Result<u64, CliError> {
        let raw = self.require(name)?;
        raw.parse::<u64>()
            .map_err(|_| CliError::usage(format!("--{name} must be a non-negative integer")))
    }

    fn reject_unknown(
        &self,
        allowed_values: &[&str],
        allowed_switches: &[&str],
    ) -> Result<(), CliError> {
        for name in self.values.keys() {
            if !allowed_values.contains(&name.as_str()) {
                return Err(CliError::usage(format!("unknown option --{name}")));
            }
        }
        for name in &self.switches {
            if !allowed_switches.contains(&name.as_str()) {
                return Err(CliError::usage(format!("unknown option --{name}")));
            }
        }
        Ok(())
    }
}

fn run(args: &[String]) -> Result<ExitCode, CliError> {
    let (command, options) = parse_args(args)?;

    if command == "help" || options.has("help") {
        print!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }

    match command.as_str() {
        "parse-cookie" => parse_cookie(&options),
        "resolve-credential" => resolve_credential(&options),
        "check-cookie" => check_cookie(&options),
        "inspect-id" => inspect_id(&options),
        "policy" => policy(&options),
        other => Err(CliError::usage(format!("unknown command {other:?}"))),
    }
}

fn parse_args(args: &[String]) -> Result<(String, Options), CliError> {
    let mut iter = args.iter();
    let command = iter
        .next()
        .ok_or_else(|| CliError::usage("missing command"))?
        .clone();

    let mut options = Options::default();

    while let Some(argument) = iter.next() {
        if argument == "-h" || argument == "--help" {
            options.switches.insert("help".to_owned());
            continue;
        }

        let Some(rest) = argument.strip_prefix("--") else {
            return Err(CliError::usage(format!(
                "unexpected argument {argument:?}; options start with --"
            )));
        };

        let (name, inline) = match rest.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (rest, None),
        };

        if name.is_empty() {
            return Err(CliError::usage("empty option name"));
        }

        let is_switch = matches!(name, "help" | "reveal" | "reveal-payload" | "secure");

        if is_switch {
            if inline.is_some() {
                return Err(CliError::usage(format!("--{name} does not take a value")));
            }
            options.switches.insert(name.to_owned());
            continue;
        }

        let value = match inline {
            Some(value) => value,
            None => iter
                .next()
                .cloned()
                .ok_or_else(|| CliError::usage(format!("--{name} requires a value")))?,
        };

        options
            .values
            .entry(name.to_owned())
            .or_default()
            .push(value);
    }

    Ok((command, options))
}

fn parse_cookie(options: &Options) -> Result<ExitCode, CliError> {
    options.reject_unknown(&["header", "session-cookie", "redact", "reveal-name"], &[])?;

    let headers: Vec<String> = options.all("header");
    if headers.is_empty() {
        return Err(CliError::usage("--header is required"));
    }

    // Join every header the same way an HTTP adapter must (RFC 6265 §5.4).
    let joined = headers.join("; ");
    let session_cookie = options.first("session-cookie").unwrap_or("session");
    let reveal = options.all("reveal-name");
    let redact = options.all("redact");

    let pairs = Pairs::parse(joined.as_bytes());
    let stats = pairs.stats();

    let rendered: Vec<Value> = pairs
        .iter()
        .map(|pair| {
            let hidden = should_redact(pair.name(), session_cookie, &reveal, &redact);
            json!({
                "name": pair.name(),
                "value": if hidden { Value::Null } else { Value::String(pair.value().to_owned()) },
                "redacted": hidden,
                "value_len": pair.value().len(),
            })
        })
        .collect();

    emit(json!({
        "pairs": rendered,
        "stats": {
            "pairs": stats.pairs,
            "skipped": stats.skipped,
            "truncated": stats.truncated,
            "too_long": stats.too_long,
        },
        "limits": {
            "max_header_bytes": MAX_COOKIE_HEADER_BYTES,
            "max_pairs": MAX_COOKIE_PAIRS,
        },
    }));

    Ok(ExitCode::SUCCESS)
}

fn resolve_credential(options: &Options) -> Result<ExitCode, CliError> {
    options.reject_unknown(&["authorization", "cookie", "cookie-name"], &["reveal"])?;

    let authorization = options.first("authorization");
    let cookie = options.first("cookie").unwrap_or("");
    let cookie_name = options.first("cookie-name").unwrap_or("session");
    let reveal = options.has("reveal");

    let pairs = Pairs::parse(cookie.as_bytes());

    match resolve(authorization, &pairs, cookie_name) {
        Ok(credentials) => {
            let token = credentials.token();
            emit(json!({
                "resolved": true,
                "source": if credentials.is_bearer() { "bearer" } else { "cookie" },
                "token_present": true,
                "token": if reveal { Value::String(token.to_owned()) } else { Value::Null },
                "token_len": token.len(),
                "token_redacted": !reveal,
            }));
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            emit(json!({
                "resolved": false,
                "source": Value::Null,
                "token_present": false,
                "category": core_category(error.category()),
                "error": error.to_string(),
            }));
            Ok(ExitCode::from(1))
        }
    }
}

fn check_cookie(options: &Options) -> Result<ExitCode, CliError> {
    options.reject_unknown(&["name", "value", "key", "key-file"], &["reveal-payload"])?;

    let name = options.require("name")?;
    let value = options.require("value")?;
    let mut specs = options.all("key");

    for path in options.all("key-file") {
        specs.extend(read_key_file(&path)?);
    }

    if specs.is_empty() {
        return Err(CliError::usage(
            "--key or --key-file is required (first is current, rest verify)",
        ));
    }

    let (first, rest) = specs
        .split_first()
        .expect("checked for an empty key list above");

    let (key_id, secret) = parse_key(first)?;
    let mut signer = CookieSigner::new(key_id, secret);

    for spec in rest {
        let (key_id, secret) = parse_key(spec)?;
        signer = signer
            .with_previous(key_id, secret)
            .map_err(|error| CliError::Configuration(error.to_string()))?;
    }

    match signer.verify(name, value) {
        Ok(payload) => {
            let mut parts = value.split('.');
            let version = parts.next().unwrap_or("");
            let key_id = parts.next().unwrap_or("");
            let reveal = options.has("reveal-payload");

            emit(json!({
                "valid": true,
                "name": name,
                "version": version,
                "key_id": key_id,
                "payload_len": payload.len(),
                "payload": if reveal { Value::String(payload.to_owned()) } else { Value::Null },
                "payload_redacted": !reveal,
            }));
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            emit(json!({
                "valid": false,
                "name": name,
                "category": sign_category(error.category()),
                "error": "signature verification failed",
            }));
            Ok(ExitCode::from(1))
        }
    }
}

fn inspect_id(options: &Options) -> Result<ExitCode, CliError> {
    options.reject_unknown(&["id"], &[])?;

    let id = options.require("id")?;

    match SessionId::new(id.to_owned()) {
        Ok(valid) => {
            emit(json!({
                "valid": true,
                "length": valid.as_str().len(),
                "min_length": MIN_SESSION_ID_BYTES,
                "max_length": MAX_SESSION_ID_BYTES,
            }));
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            emit(json!({
                "valid": false,
                "length": id.len(),
                "min_length": MIN_SESSION_ID_BYTES,
                "max_length": MAX_SESSION_ID_BYTES,
                "error": error.to_string(),
            }));
            Ok(ExitCode::from(1))
        }
    }
}

fn policy(options: &Options) -> Result<ExitCode, CliError> {
    options.reject_unknown(&["ttl", "absolute", "cookie-name"], &["secure"])?;

    let ttl = options.u64("ttl")?;
    let absolute = options.u64("absolute")?;
    let secure = options.has("secure");
    let cookie_name = options.first("cookie-name");

    let (output, configuration_valid) = policy_report(ttl, absolute, cookie_name, secure);
    emit(output);

    if configuration_valid {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn policy_report(
    ttl: u64,
    absolute: u64,
    cookie_name: Option<&str>,
    secure: bool,
) -> (Value, bool) {
    let mut output = serde_json::Map::new();
    output.insert("ttl_seconds".to_owned(), json!(ttl));
    output.insert("ttl_human".to_owned(), json!(humanize(ttl)));
    output.insert("absolute_seconds".to_owned(), json!(absolute));
    output.insert("absolute_human".to_owned(), json!(humanize(absolute)));

    let policy = Policy::new(ttl, absolute);
    let policy_valid = policy.is_ok();

    output.insert("valid".to_owned(), json!(policy_valid));
    if let Err(error) = &policy {
        output.insert("error".to_owned(), json!(error.to_string()));
    }

    let mut configuration_valid = policy_valid;

    if let Some(name) = cookie_name {
        let name_valid = is_valid_name(name);
        let prefix = Prefix::of(name);
        let requires_secure = matches!(prefix, Prefix::Host | Prefix::Secure);
        let prefix_name = match prefix {
            Prefix::Host => "host",
            Prefix::Secure => "secure",
            Prefix::None => "none",
        };
        let cookie_valid = name_valid && (!requires_secure || secure);

        output.insert("cookie_name_valid".to_owned(), json!(name_valid));
        output.insert("prefix".to_owned(), json!(prefix_name));
        output.insert("requires_secure".to_owned(), json!(requires_secure));
        output.insert("secure".to_owned(), json!(secure));
        output.insert("cookie_configuration_valid".to_owned(), json!(cookie_valid));

        configuration_valid = configuration_valid && cookie_valid;
    }

    output.insert("configuration_valid".to_owned(), json!(configuration_valid));

    (Value::Object(output), configuration_valid)
}

fn read_key_file(path: &str) -> Result<Vec<String>, CliError> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        CliError::Configuration(format!("could not read key file {path:?}: {error}"))
    })?;

    Ok(contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

fn parse_key(spec: &str) -> Result<(KeyId, SecretKey), CliError> {
    let (id, encoded) = spec
        .split_once(':')
        .ok_or_else(|| CliError::usage("--key expects keyid:base64url"))?;

    let key_id =
        KeyId::new(id).map_err(|error| CliError::usage(format!("invalid key id: {error}")))?;
    let secret = SecretKey::from_base64url(encoded)
        .map_err(|error| CliError::Configuration(format!("invalid key material: {error}")))?;

    Ok((key_id, secret))
}

fn should_redact(name: &str, session_cookie: &str, reveal: &[String], redact: &[String]) -> bool {
    if reveal.iter().any(|candidate| candidate == name) {
        return false;
    }
    if redact.iter().any(|candidate| candidate == name) {
        return true;
    }
    name == session_cookie
}

fn core_category(category: ErrorCategory) -> &'static str {
    match category {
        ErrorCategory::InvalidInput => "INVALID_INPUT",
        ErrorCategory::MissingCredential => "MISSING_CREDENTIAL",
        ErrorCategory::AmbiguousCredential => "AMBIGUOUS_CREDENTIAL",
    }
}

fn sign_category(category: SignCategory) -> &'static str {
    match category {
        SignCategory::InvalidInput => "INVALID_INPUT",
        SignCategory::Configuration => "CONFIGURATION",
        SignCategory::SignatureFailure => "SIGNATURE_FAILURE",
    }
}

fn humanize(seconds: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;

    if seconds % DAY == 0 {
        format!("{}d", seconds / DAY)
    } else if seconds % HOUR == 0 {
        format!("{}h", seconds / HOUR)
    } else if seconds % MINUTE == 0 {
        format!("{}m", seconds / MINUTE)
    } else {
        format!("{seconds}s")
    }
}

fn emit(value: Value) {
    match serde_json::to_string_pretty(&value) {
        Ok(text) => println!("{text}"),
        Err(error) => eprintln!("error: could not serialize output: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(pairs: &[(&str, &str)], switches: &[&str]) -> Options {
        let mut options = Options::default();
        for (name, value) in pairs {
            options
                .values
                .entry((*name).to_owned())
                .or_default()
                .push((*value).to_owned());
        }
        for name in switches {
            options.switches.insert((*name).to_owned());
        }
        options
    }

    #[test]
    fn parses_space_and_equals_forms() {
        let args = vec![
            "policy".to_owned(),
            "--ttl".to_owned(),
            "60".to_owned(),
            "--absolute=120".to_owned(),
        ];
        let (command, options) = parse_args(&args).unwrap();
        assert_eq!(command, "policy");
        assert_eq!(options.first("ttl"), Some("60"));
        assert_eq!(options.first("absolute"), Some("120"));
    }

    #[test]
    fn rejects_a_value_on_a_switch() {
        let args = vec!["policy".to_owned(), "--secure=1".to_owned()];
        assert!(matches!(parse_args(&args), Err(CliError::Usage(_))));
    }

    #[test]
    fn redacts_the_session_cookie_by_default() {
        let reveal = Vec::new();
        let redact = Vec::new();
        assert!(should_redact("session", "session", &reveal, &redact));
        assert!(!should_redact("theme", "session", &reveal, &redact));
    }

    #[test]
    fn reveal_wins_over_redact_and_default() {
        let reveal = vec!["session".to_owned()];
        let redact = vec!["session".to_owned()];
        assert!(!should_redact("session", "session", &reveal, &redact));
    }

    #[test]
    fn redact_adds_names_beyond_the_session_cookie() {
        let reveal = Vec::new();
        let redact = vec!["csrf".to_owned()];
        assert!(should_redact("csrf", "session", &reveal, &redact));
    }

    #[test]
    fn humanizes_common_ttls() {
        assert_eq!(humanize(604_800), "7d");
        assert_eq!(humanize(3_600), "1h");
        assert_eq!(humanize(90), "90s");
    }

    #[test]
    fn parses_a_key_spec() {
        let encoded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let (id, _secret) = parse_key(&format!("k1:{encoded}")).unwrap();
        assert_eq!(id.as_str(), "k1");
    }

    #[test]
    fn rejects_a_key_spec_without_a_separator() {
        assert!(matches!(parse_key("k1"), Err(CliError::Usage(_))));
    }

    #[test]
    fn policy_accepts_a_valid_plain_cookie() {
        let (report, valid) = policy_report(604_800, 2_592_000, Some("session"), false);
        assert!(valid);
        assert_eq!(report["valid"], true);
        assert_eq!(report["cookie_configuration_valid"], true);
        assert_eq!(report["prefix"], "none");
    }

    #[test]
    fn policy_rejects_absolute_shorter_than_idle() {
        let (report, valid) = policy_report(604_800, 60, None, false);
        assert!(!valid);
        assert_eq!(report["valid"], false);
        assert!(report.get("error").is_some());
    }

    #[test]
    fn policy_requires_secure_for_prefixed_cookies() {
        let (report, valid) = policy_report(60, 120, Some("__Host-session"), false);
        assert!(!valid);
        assert_eq!(report["requires_secure"], true);
        assert_eq!(report["cookie_configuration_valid"], false);

        let (report, valid) = policy_report(60, 120, Some("__Host-session"), true);
        assert!(valid);
        assert_eq!(report["cookie_configuration_valid"], true);
    }

    #[test]
    fn policy_rejects_a_non_token_cookie_name() {
        let (report, valid) = policy_report(60, 120, Some("bad name"), false);
        assert!(!valid);
        assert_eq!(report["cookie_name_valid"], false);
    }

    #[test]
    fn reveal_name_is_a_value_option() {
        let args = vec![
            "parse-cookie".to_owned(),
            "--header".to_owned(),
            "a=b".to_owned(),
            "--reveal-name".to_owned(),
            "a".to_owned(),
        ];
        let (_, options) = parse_args(&args).unwrap();
        assert_eq!(options.first("reveal-name"), Some("a"));
        assert!(!options.has("reveal-name"));
    }

    #[test]
    fn rejects_unknown_options() {
        let options = options(&[("bogus", "1")], &[]);
        assert!(matches!(
            options.reject_unknown(&["header"], &[]),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn reads_key_files_skipping_comments_and_blanks() {
        let path =
            std::env::temp_dir().join(format!("oxsession-devtool-keys-{}.txt", std::process::id()));
        std::fs::write(&path, "# rotation ring\n\nk2:abc\nk1:def\n").unwrap();

        let specs = read_key_file(path.to_str().unwrap()).unwrap();
        assert_eq!(specs, vec!["k2:abc".to_owned(), "k1:def".to_owned()]);

        std::fs::remove_file(&path).unwrap();
    }
}
