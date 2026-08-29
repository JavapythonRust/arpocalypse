use std::net::Ipv4Addr;
use pnet::datalink::MacAddr;

#[derive(Clone)]
pub struct Config {
    pub victim_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub victim_mac: MacAddr,
    pub gateway_mac: MacAddr,
    pub my_mac: MacAddr,
}

pub enum TxMessage {
    Frame(Vec<u8>),
    Poison,
    Restore,
    Shutdown,
}
