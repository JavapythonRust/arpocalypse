use std::sync::atomic::{
    AtomicBool,
    Ordering,
};
use std::thread;
use std::time::Duration;

use crossbeam_channel::Sender;
use pnet::datalink::DataLinkReceiver;

pub fn run(
    mut rx: Box<dyn DataLinkReceiver>,
    packet_tx: Sender<Vec<u8>>,
    running: &AtomicBool,
) {
    println!("[RX] Thread started");

    while running.load(Ordering::SeqCst) {
        match rx.next() {
            Ok(packet) => {
                let owned = packet.to_vec();

                if packet_tx.send(owned).is_err() {
                    break;
                }
            }

            Err(_) => {
                thread::sleep(Duration::from_millis(1));
            }
        }
    }

    println!("[RX] Thread stopped");
}
