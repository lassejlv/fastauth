use fastauth_core::Model;
use fastauth_core::plugin_prelude::Id;

#[derive(Model, Clone)]
struct ApiKey {
    #[model(id)]
    id: Id,
}

fn main() {}
