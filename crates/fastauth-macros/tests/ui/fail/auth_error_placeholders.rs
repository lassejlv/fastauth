use fastauth_core::AuthError;

#[derive(AuthError, Debug)]
enum UnknownField {
    #[auth_error(status = 400, message = "bad {scope}")]
    Variant { name: String },
}

#[derive(AuthError, Debug)]
enum Positional {
    #[auth_error(status = 400, message = "bad {0}")]
    Variant(String),
}

fn main() {}
