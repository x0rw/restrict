// build.rs
use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs::{read_to_string, File};
use std::io::Write;
use std::path::{Path, PathBuf};

// Todo(x0rw): This needs more work
fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set");

    let header_file = match arch.as_str() {
        "x86_64" => "unistd_64.h",
        "x86" | "i386" | "arm" => "unistd_32.h",
        "aarch64" => "unistd.h",
        other => panic!("Unsupported architecture: {}", other),
    };

    // dirs that may have unistd header
    let mut include_dirs = vec![
        PathBuf::from("/usr/include/asm-generic"), // common fallback
        PathBuf::from("/usr/include/asm"),
        PathBuf::from(format!("/usr/include/{}-linux-gnu/asm", arch)),
        PathBuf::from("/usr/include/linux"),
    ];
    // if let Ok(dir) = env::var("SYSCALL_INCLUDE_DIR") {
    //     include_dirs.insert(0, dir);
    // }

    let header_path = include_dirs
        .iter()
        .map(|dir| dir.join(&header_file))
        .find(|candidate| candidate.exists())
        .unwrap_or_else(|| {
            eprintln!("Error: Could not find `{}` in any of:", header_file);
            for dir in &include_dirs {
                eprintln!("  - {}", dir.display());
            }
            panic!("Header file `{}` not found", header_file);
        });

    println!("cargo:rerun-if-changed={}", header_path.display());

    let content = read_to_string(&header_path).expect("Failed to read syscall header file");
    let syscalls = extract_syscalls(&content);

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR environment variable not set");
    let dest_path = Path::new(&out_dir).join("syscall_gen.rs");

    let mut out = File::create(dest_path).expect("Could not create src/syscall.rs");

    out.write_all(generate_linux_syscall_enum(&syscalls, header_path).as_bytes())
        .expect("Failed to write generated syscalls");
}

fn extract_syscalls(content: &str) -> Vec<(String, u32)> {
    let re = Regex::new(r"#define\s+__NR_([A-Za-z0-9_]+)\s+(\d+)").unwrap();

    let mut map = HashMap::new();

    for cap in re.captures_iter(content) {
        let name = cap[1].to_string();
        let num: u32 = cap[2].parse().unwrap();

        // Insert only if the number is not already mapped
        // in aarch64 i found a syscall number with two aliases which causes issues
        map.entry(num).or_insert(name);
    }

    // Return sorted by syscall number
    let mut vec: Vec<_> = map.into_iter().collect();
    vec.sort_by_key(|(num, _)| *num);
    vec.into_iter().map(|(num, name)| (name, num)).collect()
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
/// Please respect proper coding styles and documentation even in generated code
fn generate_linux_syscall_enum(syscalls: &[(String, u32)], path: PathBuf) -> String {
    let mut code = String::new();

    code.push_str(&format!(
        "/// System call list generated from `{:}`",
        path.to_str()
            .unwrap_or("Err! Couldn't find or parse the syscall header")
    ));
    code.push_str(
        r#"

use crate::error::SeccompError;

impl TryFrom<i32> for Syscall {
    type Error = SeccompError;

    fn try_from(num: i32) -> Result<Self, Self::Error> {
        match num {
"#,
    );

    for (name, _num) in syscalls {
        let variant = {
            let mut chars = name.chars();
            let first = chars.next().unwrap().to_uppercase().to_string();
            first + chars.as_str()
        };
        code.push_str(&format!(
            "           x if x == Syscall::{} as i32 => Ok(Syscall::{0}),\n",
            to_camel_case(&variant),
        ));
    }

    code.push_str(
        r#"
            other => Err(SeccompError::UnsupportedSyscallID(other)),
        }
    }
}

/// Generated syscalls enum
///
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
        code.push_str(&format!("    /// `{}()` \n", variant.to_lowercase()));
        code.push_str(&format!("    {} = {},\n", to_camel_case(&variant), num));
    }

    code.push_str("}\n");
    code
}
