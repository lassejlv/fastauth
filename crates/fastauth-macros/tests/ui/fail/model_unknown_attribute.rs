use fastauth_core::Model;
use fastauth_core::plugin_prelude::Id;

#[derive(Model, Clone)]
#[model(table = "api_key")]
struct ApiKey {
    #[model(id, input)]
    id: Id,
}

fn main() {}
