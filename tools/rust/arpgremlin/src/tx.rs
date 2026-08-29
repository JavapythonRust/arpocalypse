use crossbeam_channel::Receiver;
use pnet::datalink::DataLinkSender;

use crate::config::{
    Config,
    TxMessage,
};

pub fn run(
    mut tx: Box<dyn DataLinkSender>,
    msg_rx: Receiver<TxMessage>,
    _config: Config,
) {
    println!("[TX] Thread started");

    while let Ok(message) = msg_rx.recv() {
        match message {
            TxMessage::Frame(frame) => {
                match tx.send_to(&frame, None) {
                    Some(Ok(())) => {}

                    Some(Err(error)) => {
                        eprintln!(
                            "[TX] Forward failed: {}",
                            error
                        );
                    }

                    None => {
                        eprintln!(
                            "[TX] Forward returned None"
                        );
                    }
                }
            }

            TxMessage::Poison => {
                // Keep active ARP-manipulation
                // implementation isolated here.
            }

            TxMessage::Restore => {
                // Keep restoration implementation
                // isolated here.
            }

            TxMessage::Shutdown => {
                break;
            }
        }
    }

    println!("[TX] Thread stopped");
}
