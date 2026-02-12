use anyhow::{bail, Result};

/// Scope for a schema reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    This,
    Remote { org: String, repo: String },
}

/// A parsed reference string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedRef {
    /// A type variable (e.g. `"A"`), only valid inside a parameterized schema.
    Param(String),
    /// A concrete schema reference, possibly with type arguments.
    Concrete {
        scope: Scope,
        name: String,
        args: Vec<ParsedRef>,
    },
}

/// Parse a ref string into a `ParsedRef`.
///
/// Examples:
/// - `"A"` → `Param("A")`
/// - `"@this/foo"` → `Concrete { scope: This, name: "foo", args: [] }`
/// - `"@this/foo<@this/bar>"` → with args
/// - `"@org/repo/foo<@this/bar<@this/baz>>"` → nested
pub fn parse_ref(s: &str) -> Result<ParsedRef> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty ref string");
    }

    if !s.starts_with('@') {
        // It's a param name
        return Ok(ParsedRef::Param(s.to_string()));
    }

    parse_concrete(s)
}

fn parse_concrete(s: &str) -> Result<ParsedRef> {
    // Find where angle brackets start (if any)
    let angle_start = s.find('<');

    let base = if let Some(pos) = angle_start {
        &s[..pos]
    } else {
        s
    };

    let (scope, name) = parse_scope_and_name(base)?;

    let args = if let Some(pos) = angle_start {
        // Must end with '>'
        if !s.ends_with('>') {
            bail!("ref has '<' but no matching '>' at end: {}", s);
        }
        let inner = &s[pos + 1..s.len() - 1];
        parse_comma_separated_args(inner)?
    } else {
        vec![]
    };

    Ok(ParsedRef::Concrete { scope, name, args })
}

/// Parse `@this/name` or `@org/repo/name` from a base string (no angle brackets).
fn parse_scope_and_name(base: &str) -> Result<(Scope, String)> {
    if !base.starts_with('@') {
        bail!("expected ref starting with '@', got: {}", base);
    }
    let rest = &base[1..]; // strip '@'
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.len() {
        2 if parts[0] == "this" => Ok((Scope::This, parts[1].to_string())),
        3 => Ok((
            Scope::Remote {
                org: parts[0].to_string(),
                repo: parts[1].to_string(),
            },
            parts[2].to_string(),
        )),
        _ => bail!("invalid ref format: {}", base),
    }
}

/// Parse comma-separated ref arguments, respecting nested angle brackets.
fn parse_comma_separated_args(s: &str) -> Result<Vec<ParsedRef>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(vec![]);
    }

    let mut args = vec![];
    let mut depth = 0usize;
    let mut start = 0;

    for (i, ch) in s.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => {
                if depth == 0 {
                    bail!("unmatched '>' in ref args: {}", s);
                }
                depth -= 1;
            }
            ',' if depth == 0 => {
                let arg = s[start..i].trim();
                args.push(parse_ref(arg)?);
                start = i + 1;
            }
            _ => {}
        }
    }

    if depth != 0 {
        bail!("unmatched '<' in ref args: {}", s);
    }

    // Last argument
    let arg = s[start..].trim();
    if !arg.is_empty() {
        args.push(parse_ref(arg)?);
    }

    Ok(args)
}

/// Format a ParsedRef back into its string representation.
pub fn format_ref(parsed: &ParsedRef) -> String {
    match parsed {
        ParsedRef::Param(name) => name.clone(),
        ParsedRef::Concrete { scope, name, args } => {
            let scope_str = match scope {
                Scope::This => "@this".to_string(),
                Scope::Remote { org, repo } => format!("@{}/{}", org, repo),
            };
            let mut s = format!("{}/{}", scope_str, name);
            if !args.is_empty() {
                s.push('<');
                let arg_strs: Vec<String> = args.iter().map(format_ref).collect();
                s.push_str(&arg_strs.join(", "));
                s.push('>');
            }
            s
        }
    }
}

/// Rewrite `@this/` references inside a ParsedRef to point to a remote scope.
pub fn rewrite_this_scope(parsed: &ParsedRef, org: &str, repo: &str) -> ParsedRef {
    match parsed {
        ParsedRef::Param(name) => ParsedRef::Param(name.clone()),
        ParsedRef::Concrete { scope, name, args } => {
            let new_scope = match scope {
                Scope::This => Scope::Remote {
                    org: org.to_string(),
                    repo: repo.to_string(),
                },
                other => other.clone(),
            };
            let new_args = args
                .iter()
                .map(|a| rewrite_this_scope(a, org, repo))
                .collect();
            ParsedRef::Concrete {
                scope: new_scope,
                name: name.clone(),
                args: new_args,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_param() {
        let r = parse_ref("A").unwrap();
        assert_eq!(r, ParsedRef::Param("A".to_string()));
    }

    #[test]
    fn parse_this_ref() {
        let r = parse_ref("@this/foo").unwrap();
        assert_eq!(
            r,
            ParsedRef::Concrete {
                scope: Scope::This,
                name: "foo".to_string(),
                args: vec![],
            }
        );
    }

    #[test]
    fn parse_remote_ref() {
        let r = parse_ref("@org/repo/foo").unwrap();
        assert_eq!(
            r,
            ParsedRef::Concrete {
                scope: Scope::Remote {
                    org: "org".to_string(),
                    repo: "repo".to_string(),
                },
                name: "foo".to_string(),
                args: vec![],
            }
        );
    }

    #[test]
    fn parse_parameterized_ref() {
        let r = parse_ref("@this/foo<@this/bar>").unwrap();
        assert_eq!(
            r,
            ParsedRef::Concrete {
                scope: Scope::This,
                name: "foo".to_string(),
                args: vec![ParsedRef::Concrete {
                    scope: Scope::This,
                    name: "bar".to_string(),
                    args: vec![],
                }],
            }
        );
    }

    #[test]
    fn parse_nested_parameterized() {
        let r = parse_ref(
            "@this/transceiver-message<@this/ntt-manager-message<@this/native-token-transfer>>",
        )
        .unwrap();
        assert_eq!(
            r,
            ParsedRef::Concrete {
                scope: Scope::This,
                name: "transceiver-message".to_string(),
                args: vec![ParsedRef::Concrete {
                    scope: Scope::This,
                    name: "ntt-manager-message".to_string(),
                    args: vec![ParsedRef::Concrete {
                        scope: Scope::This,
                        name: "native-token-transfer".to_string(),
                        args: vec![],
                    }],
                }],
            }
        );
    }

    #[test]
    fn parse_multiple_args() {
        let r = parse_ref("@this/foo<@this/bar, @this/baz>").unwrap();
        match r {
            ParsedRef::Concrete { args, .. } => assert_eq!(args.len(), 2),
            _ => panic!("expected concrete"),
        }
    }

    #[test]
    fn format_roundtrip() {
        let input =
            "@this/transceiver-message<@this/ntt-manager-message<@this/native-token-transfer>>";
        let parsed = parse_ref(input).unwrap();
        let formatted = format_ref(&parsed);
        assert_eq!(formatted, input);
    }

    #[test]
    fn format_roundtrip_multi_arg() {
        let input = "@this/foo<@this/bar, @this/baz>";
        let parsed = parse_ref(input).unwrap();
        let formatted = format_ref(&parsed);
        assert_eq!(formatted, input);
    }

    #[test]
    fn rewrite_scope() {
        let parsed = parse_ref("@this/foo<@this/bar>").unwrap();
        let rewritten = rewrite_this_scope(&parsed, "wormhole-foundation", "xrpl");
        assert_eq!(
            rewritten,
            ParsedRef::Concrete {
                scope: Scope::Remote {
                    org: "wormhole-foundation".to_string(),
                    repo: "xrpl".to_string(),
                },
                name: "foo".to_string(),
                args: vec![ParsedRef::Concrete {
                    scope: Scope::Remote {
                        org: "wormhole-foundation".to_string(),
                        repo: "xrpl".to_string(),
                    },
                    name: "bar".to_string(),
                    args: vec![],
                }],
            }
        );
    }
}
