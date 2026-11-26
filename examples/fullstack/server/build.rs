// Rebuilds the server when a file in migrations/ changes, so `sqlx::migrate!` embeds it.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
