use clap::Parser;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};

#[derive(Parser, Debug)]
#[command(author, version, about = "A fast, concurrent TCP port scanner with JSON export")]
struct Cli {
    #[arg(short, long)]
    ip: IpAddr,

    #[arg(short, long, default_value_t = 1)]
    start_port: u16,

    #[arg(short, long, default_value_t = 1024)]
    end_port: u16,

    #[arg(short, long, default_value_t = 1000)]
    concurrency: usize,

    /// Optional file path to export results as JSON (e.g. -o results.json)
    #[arg(short, long)]
    output: Option<String>,
}

/// Represents an individual open port finding
#[derive(Serialize, Debug, Clone)]
struct PortResult {
    port: u16,
    banner: String,
}

/// Represents the full structured scan report
#[derive(Serialize, Debug)]
struct ScanReport {
    target: IpAddr,
    start_port: u16,
    end_port: u16,
    total_open_ports: usize,
    results: Vec<PortResult>,
}

async fn scan_port(ip: IpAddr, port: u16, tx: mpsc::Sender<PortResult>) {
    let connect_timeout = Duration::from_millis(500);
    let io_timeout = Duration::from_millis(500);
    let socket_address = SocketAddr::new(ip, port);

    if let Ok(Ok(mut stream)) = tokio::time::timeout(connect_timeout, TcpStream::connect(&socket_address)).await {
        let mut banner = String::from("No banner / Unknown Service");
        let mut buf = [0; 256];

        if let Ok(Ok(n)) = tokio::time::timeout(io_timeout, stream.read(&mut buf)).await {
            if n > 0 {
                banner = String::from_utf8_lossy(&buf[..n]).to_string();
            } else {
                let probe = b"GET / HTTP/1.1\r\n\r\n";
                if let Ok(Ok(_)) = tokio::time::timeout(io_timeout, stream.write_all(probe)).await {
                    if let Ok(Ok(n_probe)) = tokio::time::timeout(io_timeout, stream.read(&mut buf)).await {
                        if n_probe > 0 {
                            banner = String::from_utf8_lossy(&buf[..n_probe]).to_string();
                        }
                    }
                }
            }
        }

        let clean_banner = banner.lines().next().unwrap_or("").trim().to_string();
        let _ = tx.send(PortResult {
            port,
            banner: clean_banner,
        }).await;
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    println!("Scanning {} from port {} to {} (Concurrency: {})...", 
             cli.ip, cli.start_port, cli.end_port, cli.concurrency);

    let (tx, mut rx) = mpsc::channel(100);
    let semaphore = Arc::new(Semaphore::new(cli.concurrency));

    for port in cli.start_port..=cli.end_port {
        let tx_clone = tx.clone();
        let ip = cli.ip;
        let sem_clone = semaphore.clone();

        tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();
            scan_port(ip, port, tx_clone).await;
        });
    }

    drop(tx);

    let mut open_ports = Vec::new();
    while let Some(result) = rx.recv().await {
        open_ports.push(result);
    }

    open_ports.sort_by_key(|k| k.port);

    println!("\nScan Complete!");
    if open_ports.is_empty() {
        println!("No open ports found.");
    } else {
        for res in &open_ports {
            println!("Port {:<5} is OPEN  |  Banner: {}", res.port, res.banner);
        }
    }

    // Export to JSON if the output flag was supplied
    if let Some(file_path) = cli.output {
        let report = ScanReport {
            target: cli.ip,
            start_port: cli.start_port,
            end_port: cli.end_port,
            total_open_ports: open_ports.len(),
            results: open_ports,
        };

        match serde_json::to_string_pretty(&report) {
            Ok(json_data) => {
                if let Ok(mut file) = File::create(&file_path) {
                    if file.write_all(json_data.as_bytes()).is_ok() {
                        println!("\nSuccessfully exported results to '{}'", file_path);
                    } else {
                        eprintln!("Failed to write data to '{}'", file_path);
                    }
                } else {
                    eprintln!("Failed to create file '{}'", file_path);
                }
            }
            Err(err) => eprintln!("Failed to serialize report to JSON: {}", err),
        }
    }
}