use fastauth_core::Fields;

#[derive(Fields, Clone)]
struct Profile {
    #[field(default = "free")]
    beta: bool,
    #[field(default = now)]
    plan: Option<String>,
    #[field(default = 3)]
    name: String,
}

fn main() {}
