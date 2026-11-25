use std::process::{Command, Output};

use fastauth_core::crypto::base64url_decode;

fn fastauth(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fastauth"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn secret_prints_an_env_line_with_64_random_bytes() {
    let first = fastauth(&["secret"]);
    assert!(first.status.success());
    let line = String::from_utf8(first.stdout).unwrap();
    let value = line
        .strip_prefix("FASTAUTH_SECRET=")
        .and_then(|v| v.strip_suffix('\n'))
        .unwrap();
    assert_eq!(base64url_decode(value).unwrap().len(), 64);

    let raw = String::from_utf8(fastauth(&["secret", "--raw"]).stdout).unwrap();
    assert_eq!(base64url_decode(raw.trim_end()).unwrap().len(), 64);
    assert_ne!(raw.trim_end(), value);
}

#[test]
fn help_explains_where_the_schema_commands_live() {
    let help = String::from_utf8(fastauth(&["--help"]).stdout).unwrap();
    assert!(
        help.contains("only a binary compiled\nfrom your code can know it"),
        "{help}"
    );
    assert!(help.contains("fastauth::cli::run(async |pool| my_app::auth::build(pool))"));
}

#[test]
fn app_commands_point_at_the_app_binary() {
    let output = fastauth(&["generate", "--out", "migrations"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with("error: `fastauth generate` runs from your app's binary."),
        "{stderr}"
    );

    let output = fastauth(&["frobnicate"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("unknown command `frobnicate`")
    );
}
