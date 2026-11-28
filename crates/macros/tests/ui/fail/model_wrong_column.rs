use fastauth_core::Model;
use fastauth_core::plugin_prelude::*;

#[derive(Model, Clone)]
#[model(table = "api_key")]
struct ApiKey {
    #[model(id)]
    id: Id,
}

fn main() {
    let _: Where<ApiKey> = ApiKey::ID.eq(3i64);
    let _: Where<User> = ApiKey::ID.eq("u1");
}
