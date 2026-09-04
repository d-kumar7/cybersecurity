use hickory_resolver::Resolver;
use hickory_resolver::config::*;
use anyhow::Result;
use clap::Parser;

/// A simple reconnaissance tool for DNS enumeration
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The target domain to scan (e.g., example.com)
    #[arg(short, long)]
    domain: String,
}

fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();
    let target_domain = cli.domain;

    println!("Gathering DNS records for: {}\n", target_domain);

    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;

    // 1. Fetch A Records (IPv4)
    println!("--- A Records (IPv4) ---");
    match resolver.ipv4_lookup(target_domain.as_str()) {
        Ok(response) => {
            for ip in response.iter() {
                println!("IPv4 Address: {}", ip);
            }
        }
        Err(_) => println!("No A records found or query failed."),
    }

    // 2. Fetch AAAA Records (IPv6)
    println!("\n--- AAAA Records (IPv6) ---");
    match resolver.ipv6_lookup(target_domain.as_str()) {
        Ok(response) => {
            for ip in response.iter() {
                println!("IPv6 Address: {}", ip);
            }
        }
        Err(_) => println!("No AAAA records found or query failed."),
    }

    // 3. Fetch MX Records (Mail Servers)
    println!("\n--- MX Records (Mail Exchange) ---");
    match resolver.mx_lookup(target_domain.as_str()) {
        Ok(response) => {
            for mx in response.iter() {
                println!("Preference: {} | Server: {}", mx.preference(), mx.exchange());
            }
        }
        Err(_) => println!("No MX records found or query failed."),
    }

    Ok(())
}