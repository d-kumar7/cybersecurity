use clap::Parser;
use colored::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[derive(Parser, Debug)]
#[command(author, version, about = "Local system security configuration auditor")]
struct Cli {
    #[arg(short, long)]
    all: bool,
}

/// Checks file permissions. 
/// If `allow_world_read` is true, mode 644 is a PASS. 
/// If false, any access by "others" is a FAIL.
fn check_file_permissions(path: &str, allow_world_read: bool) {
    match fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode();
            let others_perms = mode & 0o007;

            if others_perms == 0 {
                println!("[ {} ] {} is strictly locked down (mode: {:o})", "PASS".green().bold(), path, mode & 0o777);
            } else if allow_world_read && others_perms == 4 { // 4 is Read-Only
                println!("[ {} ] {} is world-readable, which is expected (mode: {:o})", "PASS".green().bold(), path, mode & 0o777);
            } else {
                println!("[ {} ] {} has dangerous permissions for others (mode: {:o})", "FAIL".red().bold(), path, mode & 0o777);
            }
        }
        Err(e) => {
            println!("[ {} ] Could not check {}: {}", "WARN".yellow().bold(), path, e);
        }
    }
}

fn check_ssh_root_login(path: &str) {
    if let Ok(contents) = fs::read_to_string(path) {
        let root_login_enabled = contents.lines().any(|line| {
            let trimmed = line.trim();
            !trimmed.starts_with('#') && trimmed.contains("PermitRootLogin yes")
        });

        if root_login_enabled {
            println!("[ {} ] Root login is explicitly enabled in {}", "FAIL".red().bold(), path);
        } else {
            println!("[ {} ] Root login is restricted in {}", "PASS".green().bold(), path);
        }
    } else {
        println!("[ {} ] Could not read {} (File might not exist)", "WARN".yellow().bold(), path);
    }
}

fn main() {
    let _cli = Cli::parse();
    println!("{} Starting local system audit...\n", "[*]".blue().bold());

    println!("--- File Permission Checks ---");
    // /etc/passwd must be world-readable (true)
    check_file_permissions("/etc/passwd", true);
    
    // /etc/sudoers must NEVER be world-readable (false)
    check_file_permissions("/etc/sudoers", false);
    
    println!("\n--- Service Configuration Checks ---");
    check_ssh_root_login("/etc/ssh/sshd_config"); 

    println!("\n{} Audit complete.", "[*]".blue().bold());
}