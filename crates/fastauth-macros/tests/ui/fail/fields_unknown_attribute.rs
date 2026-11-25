use fastauth_core::Fields;

#[derive(Fields, Clone)]
struct Profile {
    #[field(nullable)]
    plan: String,
}

#[derive(Fields, Clone)]
struct Score {
    #[field(default = 1.5)]
    score: i64,
}

fn main() {}
