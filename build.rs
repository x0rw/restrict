// build.rs
use regex::Regex;
use std::env;
use std::fs::{read_to_string, File};
use std::io::Write;
use std::path::Path;

// Todo(x0rw): This needs more work
fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set");

    let header_file = match arch.as_str() {
        "x86_64" | "aarch64" => "unistd_64.h",
        "x86" | "i386" | "arm" => "unistd_32.h",
        other => panic!("Unsupported architecture: {}", other),
    };

    // dirs that may have unistd header
    let mut include_dirs = vec![
        "/usr/include/asm".into(),
        format!("/usr/include/{}-linux-gnu/asm", arch),
    ];
    if let Ok(dir) = env::var("SYSCALL_INCLUDE_DIR") {
        include_dirs.insert(0, dir);
    }

    let header_path = include_dirs
        .iter()
        .map(|d| Path::new(d).join(header_file))
        .find(|p| p.exists())
        .unwrap_or_else(|| {
            panic!(
                "Could not find {} in any of: {:?}",
                header_file, include_dirs
            )
        });

    println!("cargo:rerun-if-changed={}", header_path.display());

    let content = read_to_string(&header_path).expect("Failed to read syscall header file");
    let syscalls = extract_syscalls(&content);

    let mut out = File::create("src/syscall.rs").expect("Could not create src/syscall.rs");
    out.write_all(generate_linux_syscall_enum(&syscalls).as_bytes())
        .expect("Failed to write generated syscalls");
}

fn extract_syscalls(content: &str) -> Vec<(String, u32)> {
    let re = Regex::new(r"#define\s+__NR_([A-Za-z0-9_]+)\s+(\d+)").unwrap();

    re.captures_iter(content)
        .map(|cap| (cap[1].to_string(), cap[2].parse().unwrap()))
        .collect()
}

fn to_camel_case(input: &str) -> String {
    input
        .split('_')
        .enumerate()
        .map(|(i, part)| {
            if i == 0 {
                part.to_string()
            } else {
                let mut chars = part.chars();
                let first_char = chars.next().unwrap_or_default().to_uppercase().to_string();
                let rest = chars.collect::<String>();
                first_char + &rest
            }
        })
        .collect::<String>()
}

/// generate syscall enum
fn generate_linux_syscall_enum(syscalls: &[(String, u32)]) -> String {
    let mut code = String::new();
    code.push_str(
        r#"
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Syscall {
"#,
    );

    for (name, num) in syscalls {
        let variant = {
            let mut chars = name.chars();
            let first = chars.next().unwrap().to_uppercase().to_string();
            first + chars.as_str()
        };
        code.push_str(&format!("    /// {}() \n", variant.to_lowercase()));
        code.push_str(&format!("    {} = {},\n", to_camel_case(&variant), num));
    }

    code.push_str("}\n");
    code
}
