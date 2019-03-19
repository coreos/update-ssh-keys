use std::env;
use std::process::Command;

// This runs the old python integration test-suite to ensure
// retro-compatibility.
#[test]
fn test_compat_python_suite() {
    let pytests = env::current_dir()
        .unwrap()
        .join("tests")
        .join("test_update_ssh_keys.py");
    let result = Command::new(pytests).output().unwrap();
    if !result.status.success() {
        panic!(format!(
            "\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        ));
    };
    assert!(result.status.success());
}
