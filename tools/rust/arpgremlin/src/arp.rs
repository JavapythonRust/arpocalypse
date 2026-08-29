use std::net::Ipv4Addr;

use pnet::datalink::MacAddr;

pub struct ArpInfo {
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

/*
 * ARP parsing/construction helpers go here.
 *
 
 */
