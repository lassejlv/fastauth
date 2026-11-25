use fastauth_core::Model;
use fastauth_core::plugin_prelude::Id;

#[derive(Model, Clone)]
#[model(table = "api_key")]
struct ApiKey {
    #[model(references = fastauth_core::models::User, on_delete = Delete)]
    user_id: Id,
}

#[derive(Model, Clone)]
#[model(table = "api_key_2")]
struct Other {
    #[model(on_delete = Cascade)]
    user_id: Id,
}

fn main() {}
