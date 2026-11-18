//! Parsing of request `Cookie` headers (RFC 6265bis section 5.4).
//!
//! The parser works on raw header bytes, so every adapter feeds it the same
//! input and gets the same result. Parsing never fails: malformed pairs are
//! skipped and counted in [`Stats`]. Credential lookups use
//! [`Pairs::get_unique`], which reports duplicate names as
//! [`Ambiguous::Duplicate`] instead of silently picking one.

/// Largest `Cookie` header accepted, matching the limit used by common browsers.
pub const MAX_COOKIE_HEADER_BYTES: usize = 8 * 1024;

/// Largest number of pairs read from a single header.
pub const MAX_COOKIE_PAIRS: usize = 128;

/// What a scan of a `Cookie` header saw.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Number of accepted pairs.
    pub pairs: usize,
    /// Number of non-empty segments that were not valid `name=value` pairs.
    pub skipped: usize,
    /// True when [`MAX_COOKIE_PAIRS`] was reached and remaining pairs were ignored.
    pub truncated: bool,
    /// True when the header exceeded [`MAX_COOKIE_HEADER_BYTES`] and nothing was read.
    pub too_long: bool,
}

/// Why a credential lookup could not produce a single value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ambiguous {
    /// The name appeared `count` times. On a credential cookie this is an attack.
    Duplicate {
        /// Number of occurrences, saturating at [`u16::MAX`].
        count: u16,
    },
    /// The scan stopped at [`MAX_COOKIE_PAIRS`], so a duplicate could hide later.
    Truncated,
    /// The header was larger than [`MAX_COOKIE_HEADER_BYTES`]; nothing was read.
    HeaderTooLong,
}

/// One `name=value` pair, borrowed from the header bytes.
///
/// Surrounding quotes of a quoted value are removed; the value is returned as
/// the octets between the quotes, which is what RFC 6265bis defines as the
/// cookie value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pair<'a> {
    name: &'a str,
    value: &'a str,
}

impl<'a> Pair<'a> {
    /// The cookie name, exactly as sent (names are case-sensitive).
    #[must_use]
    pub const fn name(&self) -> &'a str {
        self.name
    }

    /// The cookie value without surrounding quotes.
    #[must_use]
    pub const fn value(&self) -> &'a str {
        self.value
    }
}

/// A parsed `Cookie` header.
#[derive(Clone, Copy, Debug)]
pub struct Pairs<'a> {
    src: &'a [u8],
    too_long: bool,
}

impl<'a> Pairs<'a> {
    /// Parse the value of one `Cookie` header.
    ///
    /// A request may carry several `Cookie` headers; join them with `"; "`
    /// before calling this, as RFC 6265 section 5.4 requires.
    #[must_use]
    pub fn parse(header: &'a [u8]) -> Self {
        Self {
            src: header,
            too_long: header.len() > MAX_COOKIE_HEADER_BYTES,
        }
    }

    /// Every accepted pair, in header order, up to [`MAX_COOKIE_PAIRS`].
    #[must_use]
    pub fn iter(&self) -> Iter<'a> {
        Iter {
            src: self.src,
            pos: 0,
            emitted: 0,
            too_long: self.too_long,
        }
    }

    /// The value of the first pair named exactly `name`.
    ///
    /// Use this for preferences. Use [`Pairs::get_unique`] for credentials.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&'a str> {
        self.iter()
            .find(|pair| pair.name == name)
            .map(|pair| pair.value)
    }

    /// Every value of `name`, in header order.
    ///
    /// Cookies may legitimately repeat when they were set for different paths.
    #[must_use]
    pub fn get_all<'n>(&'n self, name: &'n str) -> impl Iterator<Item = &'a str> + 'n {
        self.iter()
            .filter(move |pair| pair.name == name)
            .map(|pair| pair.value)
    }

    /// The value of the only pair named `name`.
    ///
    /// # Errors
    ///
    /// - [`Ambiguous::HeaderTooLong`] when the header was not read at all.
    /// - [`Ambiguous::Duplicate`] when `name` appears more than once.
    /// - [`Ambiguous::Truncated`] when the scan hit [`MAX_COOKIE_PAIRS`] and
    ///   duplicates could not be ruled out.
    pub fn get_unique(&self, name: &str) -> Result<Option<&'a str>, Ambiguous> {
        if self.too_long {
            return Err(Ambiguous::HeaderTooLong);
        }

        let mut count: u16 = 0;
        let mut first: Option<&'a str> = None;

        for pair in self.iter() {
            if pair.name == name {
                count = count.saturating_add(1);
                if first.is_none() {
                    first = Some(pair.value);
                }
            }
        }

        if count > 1 {
            return Err(Ambiguous::Duplicate { count });
        }
        if self.stats().truncated {
            return Err(Ambiguous::Truncated);
        }
        Ok(first)
    }

    /// Count what a full scan of the header sees.
    #[must_use]
    pub fn stats(&self) -> Stats {
        if self.too_long {
            return Stats {
                too_long: true,
                ..Stats::default()
            };
        }

        let mut stats = Stats::default();
        for segment in self.src.split(|byte| *byte == b';') {
            if parse_pair(segment).is_some() {
                if stats.pairs == MAX_COOKIE_PAIRS {
                    stats.truncated = true;
                    break;
                }
                stats.pairs += 1;
            } else if !trim_ows(segment).is_empty() {
                stats.skipped += 1;
            }
        }
        stats
    }
}

/// Iterator over the pairs of a [`Pairs`].
#[derive(Clone, Debug)]
pub struct Iter<'a> {
    src: &'a [u8],
    pos: usize,
    emitted: usize,
    too_long: bool,
}

impl<'a> Iterator for Iter<'a> {
    type Item = Pair<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.too_long || self.emitted == MAX_COOKIE_PAIRS {
            return None;
        }

        while self.pos < self.src.len() {
            let rest = &self.src[self.pos..];
            let (segment, next) = match rest.iter().position(|byte| *byte == b';') {
                Some(index) => (&rest[..index], self.pos + index + 1),
                None => (rest, self.src.len()),
            };
            self.pos = next;

            if let Some(pair) = parse_pair(segment) {
                self.emitted += 1;
                return Some(pair);
            }
        }

        None
    }
}

/// Whether `name` is a valid cookie name, i.e. an RFC 7230 token.
///
/// Use this to validate configured cookie names at startup.
#[must_use]
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_token_byte)
}

fn parse_pair(segment: &[u8]) -> Option<Pair<'_>> {
    let segment = trim_ows(segment);
    let equals = segment.iter().position(|byte| *byte == b'=')?;

    let name = trim_ows(&segment[..equals]);
    let value = trim_ows(&segment[equals + 1..]);

    if !name.iter().all(|byte| is_token_byte(*byte)) || name.is_empty() {
        return None;
    }

    let value = match value {
        [b'"', inner @ .., b'"'] => inner,
        other => other,
    };

    if !value.iter().all(|byte| is_cookie_octet(*byte)) {
        return None;
    }

    Some(Pair {
        // Both slices were validated as ASCII above.
        name: std::str::from_utf8(name).ok()?,
        value: std::str::from_utf8(value).ok()?,
    })
}

fn trim_ows(bytes: &[u8]) -> &[u8] {
    let is_ows = |byte: &u8| matches!(*byte, b' ' | b'\t');
    let start = bytes
        .iter()
        .position(|byte| !is_ows(byte))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !is_ows(byte))
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

pub(crate) fn is_cookie_octet(byte: u8) -> bool {
    matches!(
        byte,
        0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(header: &str) -> Vec<&str> {
        Pairs::parse(header.as_bytes())
            .iter()
            .map(|pair| pair.name())
            .collect()
    }

    #[test]
    fn reads_pairs_in_order() {
        assert_eq!(names("a=1; b=2; c=3"), ["a", "b", "c"]);
    }

    #[test]
    fn trims_optional_whitespace() {
        let pairs = Pairs::parse(b"  a = 1 ;\tb=2\t");
        assert_eq!(pairs.get("a"), Some("1"));
        assert_eq!(pairs.get("b"), Some("2"));
    }

    #[test]
    fn skips_malformed_pairs() {
        let stats = Pairs::parse(b"a=1; not-a-pair; =2; b=3").stats();
        assert_eq!(stats.pairs, 2);
        assert_eq!(stats.skipped, 2);
    }

    #[test]
    fn names_are_case_sensitive() {
        assert_eq!(Pairs::parse(b"Theme=dark").get("theme"), None);
        assert_eq!(Pairs::parse(b"Theme=dark").get("Theme"), Some("dark"));
    }

    #[test]
    fn strips_surrounding_quotes() {
        assert_eq!(Pairs::parse(b"a=\"1\"").get("a"), Some("1"));
        assert_eq!(Pairs::parse(b"a=\"\"").get("a"), Some(""));
    }

    #[test]
    fn rejects_bytes_outside_cookie_octets() {
        assert_eq!(Pairs::parse(b"a=1,2").get("a"), None);
        assert_eq!(Pairs::parse(b"a=x\\y").get("a"), None);
        assert_eq!(Pairs::parse(b"a=\x7f").get("a"), None);
    }

    #[test]
    fn empty_value_is_valid() {
        assert_eq!(Pairs::parse(b"a=").get("a"), Some(""));
    }

    #[test]
    fn get_returns_first_match() {
        assert_eq!(Pairs::parse(b"a=1; a=2").get("a"), Some("1"));
    }

    #[test]
    fn get_all_returns_every_match() {
        let values: Vec<&str> = Pairs::parse(b"c=2; t=1; c=1").get_all("c").collect();
        assert_eq!(values, ["2", "1"]);
    }

    #[test]
    fn get_unique_rejects_duplicates() {
        assert_eq!(
            Pairs::parse(b"sid=a; sid=b").get_unique("sid"),
            Err(Ambiguous::Duplicate { count: 2 })
        );
        assert_eq!(
            Pairs::parse(b"sid=a; theme=b").get_unique("sid"),
            Ok(Some("a"))
        );
        assert_eq!(Pairs::parse(b"theme=b").get_unique("sid"), Ok(None));
    }

    #[test]
    fn oversized_header_reads_nothing() {
        let header = format!("a={}", "x".repeat(MAX_COOKIE_HEADER_BYTES));
        let pairs = Pairs::parse(header.as_bytes());
        assert_eq!(pairs.get("a"), None);
        assert!(pairs.stats().too_long);
        assert_eq!(pairs.get_unique("a"), Err(Ambiguous::HeaderTooLong));
    }

    #[test]
    fn pair_limit_truncates_scan() {
        let header = (0..MAX_COOKIE_PAIRS + 10)
            .map(|index| format!("c{index}=1"))
            .collect::<Vec<_>>()
            .join("; ");
        let pairs = Pairs::parse(header.as_bytes());
        assert_eq!(pairs.iter().count(), MAX_COOKIE_PAIRS);
        assert!(pairs.stats().truncated);
        assert_eq!(pairs.get_unique("missing"), Err(Ambiguous::Truncated));
    }

    #[test]
    fn validates_names() {
        assert!(is_valid_name("session"));
        assert!(is_valid_name("__Host-sid"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("bad name"));
        assert!(!is_valid_name("bad;name"));
    }
}
