use std::net::Ipv4Addr;
use ipnetwork::Ipv4Network;
use pnet::datalink;
use pnet::datalink::MacAddr;

pub fn parsemac(input: &str) -> Result<MacAddr, String> {
    let parts: Vec<&str> = input.split(':').collect();

    if parts.len() != 6 {
        return Err("MAC must have 6 parts".to_string());
    }

    let mut octets = [0u8; 6];

    for (i, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(format!(
                "Part {} must be 2 hex digits",
                i
            ));
        }

        octets[i] = u8::from_str_radix(part, 16)
            .map_err(|_| format!("Invalid hex: '{}'", part))?;
    }

    Ok(MacAddr::from(octets))
}

pub fn check_ip_forwarding() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("sysctl")
            .arg("-n")
            .arg("net.inet.ip.forwarding")
            .output()
            .map_err(|e| format!("sysctl failed: {}", e))?;

        if String::from_utf8_lossy(&out.stdout).trim() == "1" {
            println!("IP forwarding enabled");
            Ok(())
        } else {
            Err("IP forwarding disabled".into())
        }
    }

    #[cfg(target_os = "linux")]
    {
        let val =
            std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
                .map_err(|e| format!("read /proc failed: {}", e))?;

        if val.trim() == "1" {
            println!("IP forwarding enabled");
            Ok(())
        } else {
            Err("IP forwarding disabled".into())
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        println!("Cannot automatically check IP forwarding");
        Ok(())
    }
}

pub fn find_interface(target: Ipv4Addr) -> Option<String> {
    for iface in datalink::interfaces() {
        if iface.is_loopback() {
            continue;
        }

        for ipnet in &iface.ips {
            if let std::net::IpAddr::V4(local) = ipnet.ip() {
                if let Ok(net) =
                    Ipv4Network::new(local, ipnet.prefix())
                {
                    if net.contains(target) {
                        return Some(iface.name);
                    }
                }
            }
        }
    }

    None
}
