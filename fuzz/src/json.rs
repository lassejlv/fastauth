//! Arbitrary JSON values, with a bias towards the shapes fastauth stores (`Value`'s
//! externally tagged variants) so forged payloads reach the decoders.

use arbitrary::Arbitrary;
use serde_json::{Map, Value, json};

#[derive(Arbitrary, Debug, Clone)]
pub enum ArbJson {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<ArbJson>),
    Obj(Vec<(String, ArbJson)>),
    /// `{"Text": ..}`, `{"Int": ..}` and the other `fastauth_core::value::Value` variants.
    Tagged(u8, Box<ArbJson>),
}

const TAGS: [&str; 7] = ["Null", "Bool", "Int", "Text", "Bytes", "Timestamp", "Json"];

impl ArbJson {
    pub fn to_json(&self) -> Value {
        match self {
            ArbJson::Null => Value::Null,
            ArbJson::Bool(b) => json!(b),
            ArbJson::Int(i) => json!(i),
            ArbJson::Float(f) => {
                serde_json::Number::from_f64(*f).map_or(Value::Null, Value::Number)
            }
            ArbJson::Str(s) => json!(s),
            ArbJson::Arr(items) => Value::Array(items.iter().map(ArbJson::to_json).collect()),
            ArbJson::Obj(fields) => Value::Object(
                fields
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_json()))
                    .collect::<Map<_, _>>(),
            ),
            ArbJson::Tagged(tag, value) => {
                let tag = TAGS[usize::from(*tag) % TAGS.len()];
                if tag == "Null" {
                    json!("Null")
                } else {
                    json!({ tag: value.to_json() })
                }
            }
        }
    }
}
