use anyhow::{bail, Result};
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;

/// Parsed representation of a field type string (e.g. "u8", "address", "bytes20").
///
/// Parsed once during deserialization so that parse/serialize can dispatch on
/// the enum instead of re-matching strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    U8,
    U16,
    U32,
    U64,
    Address,
    String32,
    Hex,
    Bytes(usize),
}

impl FieldType {
    pub fn from_type_str(s: &str) -> Result<Self, String> {
        match s {
            "u8" => Ok(FieldType::U8),
            "u16" => Ok(FieldType::U16),
            "u32" => Ok(FieldType::U32),
            "u64" => Ok(FieldType::U64),
            "address" => Ok(FieldType::Address),
            "string32" => Ok(FieldType::String32),
            "hex" => Ok(FieldType::Hex),
            other if other.starts_with("bytes") => {
                let n: usize = other[5..]
                    .parse()
                    .map_err(|_| format!("invalid bytesN type: {}", other))?;
                Ok(FieldType::Bytes(n))
            }
            other => Err(format!("unknown field type: {}", other)),
        }
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FieldType::U8 => write!(f, "u8"),
            FieldType::U16 => write!(f, "u16"),
            FieldType::U32 => write!(f, "u32"),
            FieldType::U64 => write!(f, "u64"),
            FieldType::Address => write!(f, "address"),
            FieldType::String32 => write!(f, "string32"),
            FieldType::Hex => write!(f, "hex"),
            FieldType::Bytes(n) => write!(f, "bytes{}", n),
        }
    }
}

/// A single field in a schema.
#[derive(Debug, Clone)]
pub enum Field {
    Const {
        name: String,
        value: String,
    },
    Zeros(usize),
    /// A reference to another schema. If `name` is Some, the parsed result is
    /// nested under that key instead of merged flat.
    Ref {
        ref_: String,
        name: Option<String>,
    },
    LengthPrefix(String),
    Named {
        name: String,
        field_type: FieldType,
        help: Option<String>,
    },
    /// An array of schemas, repeated `count_field` times.
    /// JSON: `{"name": "sigs", "repeat": "sig-count", "ref": "@this/guardian-signature"}`
    Repeat {
        name: String,
        count_field: String,
        ref_: String,
    },
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldVisitor;

        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = Field;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a field object")
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Field, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut const_val: Option<String> = None;
                let mut zeros_val: Option<usize> = None;
                let mut ref_val: Option<String> = None;
                let mut length_prefix_val: Option<String> = None;
                let mut repeat_val: Option<String> = None;
                let mut name_val: Option<String> = None;
                let mut type_val: Option<String> = None;
                let mut help_val: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "const" => const_val = Some(map.next_value()?),
                        "zeros" => zeros_val = Some(map.next_value()?),
                        "ref" => ref_val = Some(map.next_value()?),
                        "length_prefix" => length_prefix_val = Some(map.next_value()?),
                        "repeat" => repeat_val = Some(map.next_value()?),
                        "name" => name_val = Some(map.next_value()?),
                        "type" => type_val = Some(map.next_value()?),
                        "help" => help_val = Some(map.next_value()?),
                        _ => {
                            let _ = map.next_value::<serde_json::Value>()?;
                        }
                    }
                }

                if let Some(c) = const_val {
                    let name = name_val
                        .ok_or_else(|| de::Error::custom("const field requires a 'name'"))?;
                    Ok(Field::Const { name, value: c })
                } else if let Some(z) = zeros_val {
                    Ok(Field::Zeros(z))
                } else if let Some(repeat) = repeat_val {
                    let name = name_val
                        .ok_or_else(|| de::Error::custom("repeat field requires a 'name'"))?;
                    let ref_ = ref_val
                        .ok_or_else(|| de::Error::custom("repeat field requires a 'ref'"))?;
                    Ok(Field::Repeat {
                        name,
                        count_field: repeat,
                        ref_,
                    })
                } else if let Some(r) = ref_val {
                    Ok(Field::Ref {
                        ref_: r,
                        name: name_val,
                    })
                } else if let Some(lp) = length_prefix_val {
                    Ok(Field::LengthPrefix(lp))
                } else if let (Some(name), Some(ty)) = (name_val, type_val) {
                    let field_type =
                        FieldType::from_type_str(&ty).map_err(|e| de::Error::custom(e))?;
                    Ok(Field::Named {
                        name,
                        field_type,
                        help: help_val,
                    })
                } else {
                    Err(de::Error::custom("unrecognized field shape"))
                }
            }
        }

        deserializer.deserialize_map(FieldVisitor)
    }
}

/// A schema loaded from a file. Supports two JSON shapes:
/// - Bare array: `[{...}, {...}]` → fields only
/// - Object: `{ "about": ..., "params": [...], "fields": [...], "ref": "..." }`
#[derive(Debug, Clone)]
pub struct Schema {
    pub about: Option<String>,
    pub params: Vec<String>,
    pub fields: Option<Vec<Field>>,
    pub ref_: Option<String>,
}

impl<'de> Deserialize<'de> for Schema {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SchemaVisitor;

        impl<'de> Visitor<'de> for SchemaVisitor {
            type Value = Schema;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a schema (array or object)")
            }

            // Bare array shape
            fn visit_seq<A>(self, seq: A) -> std::result::Result<Schema, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let fields: Vec<Field> =
                    Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
                Ok(Schema {
                    about: None,
                    params: vec![],
                    fields: Some(fields),
                    ref_: None,
                })
            }

            // Object shape
            fn visit_map<M>(self, mut map: M) -> std::result::Result<Schema, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut about: Option<String> = None;
                let mut params: Option<Vec<String>> = None;
                let mut fields: Option<Vec<Field>> = None;
                let mut ref_: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "about" => about = Some(map.next_value()?),
                        "params" => params = Some(map.next_value()?),
                        "fields" => fields = Some(map.next_value()?),
                        "ref" => ref_ = Some(map.next_value()?),
                        _ => {
                            let _ = map.next_value::<serde_json::Value>()?;
                        }
                    }
                }

                Ok(Schema {
                    about,
                    params: params.unwrap_or_default(),
                    fields,
                    ref_,
                })
            }
        }

        deserializer.deserialize_any(SchemaVisitor)
    }
}

/// Get the user-visible name of a field, if it has one.
fn field_name(field: &Field) -> Option<&str> {
    match field {
        Field::Named { name, .. } | Field::Const { name, .. } | Field::Repeat { name, .. } => {
            Some(name.as_str())
        }
        Field::Ref {
            name: Some(name), ..
        } => Some(name.as_str()),
        _ => None,
    }
}

/// Validate structural invariants of a schema's field list.
fn validate_schema(schema: &Schema) -> Result<()> {
    if let Some(ref fields) = schema.fields {
        // Check for duplicate field names
        let mut names = HashSet::new();
        for field in fields {
            if let Some(name) = field_name(field) {
                if !names.insert(name) {
                    bail!("duplicate field name: '{}'", name);
                }
            }
        }

        // Check LengthPrefix is followed by a Ref
        for (i, field) in fields.iter().enumerate() {
            if matches!(field, Field::LengthPrefix(_)) {
                match fields.get(i + 1) {
                    Some(Field::Ref { .. }) => {} // OK
                    _ => bail!("length_prefix must be followed by a ref field"),
                }
            }
        }
    }
    Ok(())
}

/// Parse a schema from a JSON value.
pub fn parse_schema(value: serde_json::Value) -> Result<Schema> {
    let schema: Schema = serde_json::from_value(value)?;
    if schema.fields.is_none() && schema.ref_.is_none() {
        bail!("schema must have at least `fields` or `ref`");
    }
    validate_schema(&schema)?;
    Ok(schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_array() {
        let json = serde_json::json!([
            {"name": "prefix", "const": "AABB"},
            {"name": "x", "type": "u8"}
        ]);
        let schema = parse_schema(json).unwrap();
        assert!(schema.about.is_none());
        assert!(schema.params.is_empty());
        assert!(schema.ref_.is_none());
        let fields = schema.fields.unwrap();
        assert_eq!(fields.len(), 2);
        assert!(
            matches!(&fields[0], Field::Const { name, value } if name == "prefix" && value == "AABB")
        );
        assert!(
            matches!(&fields[1], Field::Named { name, field_type, .. } if name == "x" && *field_type == FieldType::U8)
        );
    }

    #[test]
    fn const_requires_name() {
        let json = serde_json::json!([
            {"const": "AABB"}
        ]);
        assert!(parse_schema(json).is_err());
    }

    #[test]
    fn parse_object_with_ref() {
        let json = serde_json::json!({
            "about": "test",
            "ref": "@this/foo<@this/bar>"
        });
        let schema = parse_schema(json).unwrap();
        assert_eq!(schema.about.as_deref(), Some("test"));
        assert_eq!(schema.ref_.as_deref(), Some("@this/foo<@this/bar>"));
    }

    #[test]
    fn parse_parameterized() {
        let json = serde_json::json!({
            "params": ["A"],
            "fields": [
                {"zeros": 32},
                {"ref": "A"}
            ]
        });
        let schema = parse_schema(json).unwrap();
        assert_eq!(schema.params, vec!["A"]);
        let fields = schema.fields.unwrap();
        assert_eq!(fields.len(), 2);
        assert!(matches!(&fields[0], Field::Zeros(32)));
        assert!(matches!(&fields[1], Field::Ref { ref_, name: None } if ref_ == "A"));
    }

    #[test]
    fn reject_empty_schema() {
        let json = serde_json::json!({"about": "empty"});
        assert!(parse_schema(json).is_err());
    }

    #[test]
    fn reject_duplicate_field_names() {
        let json = serde_json::json!([
            {"name": "x", "type": "u8"},
            {"name": "x", "type": "u16"}
        ]);
        let err = parse_schema(json).unwrap_err().to_string();
        assert!(err.contains("duplicate field name"), "error was: {}", err);
    }

    #[test]
    fn reject_length_prefix_at_end() {
        let json = serde_json::json!([
            {"length_prefix": "u16"}
        ]);
        let err = parse_schema(json).unwrap_err().to_string();
        assert!(
            err.contains("length_prefix must be followed"),
            "error was: {}",
            err
        );
    }

    #[test]
    fn reject_unknown_field_type() {
        let json = serde_json::json!([
            {"name": "x", "type": "float64"}
        ]);
        assert!(parse_schema(json).is_err());
    }
}
