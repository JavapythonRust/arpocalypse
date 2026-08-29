use std::net::Ipv4Addr;

use etherparse::{
    NetSlice,
    SlicedPacket,
};
use pnet::datalink::MacAddr;
use pnet::packet::{
    ethernet::EthernetPacket,
    ipv4::Ipv4Packet,
};

use etherparse::EtherType;

pub struct ParsedIpv4 {
    pub source_mac: MacAddr,
    pub destination_mac: MacAddr,
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub payload: Vec<u8>,
}

pub fn parse_ipv4(packet: &[u8]) -> Option<ParsedIpv4> {
    let eth = EthernetPacket::new(packet)?;

    if eth.get_ethertype() != EtherType::IPV4 {
        return None;
    }

    let ipv4 = Ipv4Packet::new(eth.payload())?;

    Some(ParsedIpv4 {
        source_mac: eth.get_source(),
        destination_mac: eth.get_destination(),
        source_ip: ipv4.get_source(),
        destination_ip: ipv4.get_destination(),
        payload: ipv4.packet().to_vec(),
    })
}

pub fn parse_arp(
    packet: &[u8],
) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let sliced = SlicedPacket::from_ethernet(packet).ok()?;

    if let Some(NetSlice::Arp(arp)) = sliced.net {
        let sender_ip: Ipv4Addr =
            arp.sender_protocol_addr.into();

        let target_ip: Ipv4Addr =
            arp.target_protocol_addr.into();

        return Some((sender_ip, target_ip));
    }

    None
}
