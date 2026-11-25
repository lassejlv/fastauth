use fastauth_core::plugin_prelude::*;
use fastauth_core::{AuthError, Fields, Model};

#[derive(Fields, Clone)]
#[fields(table = Session)]
pub struct Device {
    /// Shown on the sessions page.
    #[field(default = "unknown", input, unique, index, rename = "device_name")]
    pub name: String,
    #[field(default = 0, input = false, returned = false)]
    pub r#type: i64,
    #[field(default = true)]
    pub trusted: Option<bool>,
}

#[derive(Model, Clone)]
#[model(table = "device_log")]
pub struct DeviceLog {
    #[model(id)]
    pub id: Id,
    #[model(references = Session, on_delete = SetNull)]
    pub session_id: Option<Id>,
    #[model(references = User)]
    pub user_id: Id,
    #[model(unique, index, hidden, default = "")]
    pub fingerprint: String,
    #[model(default = -5)]
    pub score: i64,
    #[model(default = now)]
    pub created_at: OffsetDateTime,
}

#[derive(AuthError, Debug)]
pub enum Generic<T: std::fmt::Display> {
    #[auth_error(status = 400, message = "bad {value}")]
    Bad { value: T },
    #[auth_error(status = 500, message = "tuple")]
    Tuple(T),
}

fn main() {
    let _: Col<Device, i64> = Device::TYPE;
    let _: Where<Session> = Device::NAME.eq("laptop");
    let _: Where<DeviceLog> = DeviceLog::SESSION_ID.is_null();
    let _ = AuthError::from(Generic::Bad { value: 1 });
    let _ = <Generic<u8> as ErrorCodes>::CODES;
}
