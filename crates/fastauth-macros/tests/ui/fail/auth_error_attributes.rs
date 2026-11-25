use fastauth_core::AuthError;

#[derive(AuthError, Debug)]
enum MissingStatus {
    #[auth_error(message = "no status")]
    Variant,
}

#[derive(AuthError, Debug)]
enum BadStatus {
    #[auth_error(status = 42, message = "too low")]
    Variant,
}

#[derive(AuthError, Debug)]
#[auth_error(code = "X")]
enum UnknownAttribute {
    #[auth_error(status = 400, message = "x")]
    Variant,
}

fn main() {}
