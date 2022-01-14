use serde::Serialize;
use wasm_bindgen::JsValue;

#[derive(Serialize)]
pub enum XxxDhError {
    InvalidKeyBytes,
    ProtocolError(String),
}

impl From<XxxDhError> for JsValue {
    fn from(val: XxxDhError) -> Self {
        serde_wasm_bindgen::to_value(&val).unwrap()
    }
}
