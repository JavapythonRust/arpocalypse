use std::sync::atomic::{
    AtomicBool,
    Ordering,
};
use std::time::{
    Duration,
    Instant,
};

use crossbeam_channel::{
    select,
    Receiver,
    Sender,
};

use rand::Rng;

use pnet::packet::ethernet::EthernetPacket;

use crate::config::{
    Config,
    TxMessage,
};
use crate::parser::{
    parse_arp,
    parse_ipv4,
};

pub fn run(
    packet_rx: Receiver<Vec<u8>>,
    tx_msg_tx: Sender<TxMessage>,
    config: Config,
    running: &AtomicBool,
) {
    println!("[PROCESS] Thread started");

    let mut last_event = Instant::now();

    let mut rng = rand::thread_rng();
    let mut next_interval: u64 =
        rng.gen_range(17..24);

    let timer =
        crossbeam_channel::tick(
            Duration::from_secs(1),
        );

    while running.load(Ordering::SeqCst) {
        select! {
            recv(packet_rx) -> message => {
                let packet = match message {
                    Ok(packet) => packet,
                    Err(_) => break,
                };

                if packet.len() < 14 {
                    continue;
                }

                let eth = match EthernetPacket::new(&packet) {
                    Some(packet) => packet,
                    None => continue,
                };

                let source = eth.get_source();
                let destination = eth.get_destination();

                if destination != config.my_mac {
                    continue;
                }

                if source == config.my_mac {
                    continue;
                }

                if parse_ipv4(&packet).is_some() {
                    /*
                     * Packet inspection/forwarding decision
                     * belongs here.
                     */
                }

                if let Some((sender_ip, target_ip)) =
                    parse_arp(&packet)
                {
                    let involves_victim =
                        sender_ip == config.victim_ip ||
                        target_ip == config.victim_ip;

                    let involves_gateway =
                        sender_ip == config.gateway_ip ||
                        target_ip == config.gateway_ip;

                    if involves_victim &&
                       involves_gateway
                    {
                        println!(
                            "[PROCESS] ARP event: {} -> {}",
                            sender_ip,
                            target_ip
                        );

                        last_event = Instant::now();

                        next_interval =
                            rng.gen_range(17..24);
                    }
                }
            }

            recv(timer) -> _ => {
                if last_event.elapsed()
                    >= Duration::from_secs(next_interval)
                {
                    /*
                     * Trigger whatever authorized
                     * lab-network action your TX
                     * layer is configured to perform.
                     */
                    last_event = Instant::now();
                    next_interval =
                        rng.gen_range(17..24);
                }
            }
        }
    }

    let _ = tx_msg_tx.send(TxMessage::Restore);
    let _ = tx_msg_tx.send(TxMessage::Shutdown);

    println!("[PROCESS] Thread stopped");
}
