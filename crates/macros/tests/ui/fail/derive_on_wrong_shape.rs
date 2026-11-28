use fastauth_core::{AuthError, Fields, Model};

#[derive(Fields, Clone)]
struct Tuple(bool);

#[derive(Model, Clone)]
#[model(table = "generic")]
struct Generic<T> {
    value: T,
}

#[derive(AuthError, Debug)]
struct NotAnEnum;

fn main() {}
