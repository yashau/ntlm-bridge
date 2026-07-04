use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=NTLM_BRIDGE_VERSION");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_TYPE");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");
    println!("cargo:rerun-if-changed=.git/HEAD");

    let version = explicit_version()
        .or_else(github_tag_version)
        .or_else(git_exact_tag)
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    println!("cargo:rustc-env=NTLM_BRIDGE_VERSION={version}");
}

fn explicit_version() -> Option<String> {
    std::env::var("NTLM_BRIDGE_VERSION")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

fn github_tag_version() -> Option<String> {
    let ref_type = std::env::var("GITHUB_REF_TYPE").ok()?;
    if ref_type != "tag" {
        return None;
    }
    std::env::var("GITHUB_REF_NAME")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

fn git_exact_tag() -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--exact-match"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|v| !v.is_empty())
}
