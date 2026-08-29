# arpocalypse
ARPocalypse Gremlin

Gremlin for short.

A Raspberry Pi 5-based, Flipper Zero-inspired security and networking device programmed in Python and Rust.

The Gremlin has a TUI that brings together my own tools and existing Linux tools such as Nmap.

Features





Network discovery



Security testing



Packet and protocol experiments



Custom Python tools



Custom Rust tools



Linux networking tools



Nmap integration



TUI-based interface

Hardware

The Gremlin is built around a Raspberry Pi 5 with additional sensors and hardware.

Enclosure and other physical parts are 3D printed 

Design and components may change.

Software

The project uses:





Python



Rust



Linux



Nmap



Other standard Linux networking tools

I use existing tools where they already do what I need and write my own when I want different behavior or want to experiment with something myself.

TUI

The TUI provides a single interface for the Gremlin's tools.

It can launch custom programs as well as existing Linux utilities, including Nmap.

⚠️ Warning

The Gremlin can perform actions that may disrupt networks or devices.

It can't tell the difference between a lab network and a public network.

You can.

Only use it on systems and networks you own or have explicit permission to test.



Status

Work in progress.

The hardware and software are still being developed and may change frequently.

License

This project is licensed under the GNU General Public License v3.0.

See LICENSE for the full license text.
