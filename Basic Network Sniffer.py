#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🕵️‍♂️  CodeAlpha Network Sniffer - By Ansh Gadhia (2025)         ║
║   A fun, colorful, and educational packet sniffer!                 ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import socket
import struct
import textwrap
import sys
import argparse
from datetime import datetime
import os

# ANSI color codes for pretty output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    print(f"""{Colors.HEADER}
╔══════════════════════════════════════════════════════════════════════╗
║   🕵️‍♂️  CodeAlpha Network Sniffer - By Ansh Gadhia (2025)         ║
║   A fun, colorful, and educational packet sniffer!                 ║
╚══════════════════════════════════════════════════════════════════════╝
{Colors.ENDC}""")

def list_interfaces():
    """List available interfaces (Linux only)"""
    ifaces = []
    try:
        for iface in os.listdir('/sys/class/net/'):
            ifaces.append(iface)
    except Exception:
        pass
    return ifaces

class PacketSniffer:
    def __init__(self, interface=None, count=None, protocol_filter=None, log_file=None):
        self.interface = interface
        self.count = count
        self.protocol_filter = protocol_filter
        self.packet_count = 0
        self.stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        self.log_file = log_file
        if log_file:
            with open(log_file, 'w') as f:
                f.write("timestamp,protocol,src_ip,dest_ip,src_port,dest_port,length\n")

    def create_socket(self):
        """Create a raw socket for packet capture"""
        try:
            if sys.platform.startswith('win'):
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                if self.interface:
                    sock.bind((self.interface, 0))
            return sock
        except PermissionError:
            print(f"{Colors.FAIL}Error: Root/Administrator privileges required for packet capture!{Colors.ENDC}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.FAIL}Error creating socket: {e}{Colors.ENDC}")
            sys.exit(1)

    def parse_ethernet_header(self, data):
        """Parse Ethernet header"""
        eth_header = struct.unpack('!6s6sH', data[:14])
        dest_mac = ':'.join(f'{b:02x}' for b in eth_header[0])
        src_mac = ':'.join(f'{b:02x}' for b in eth_header[1])
        eth_type = eth_header[2]
        
        return {
            'dest_mac': dest_mac,
            'src_mac': src_mac,
            'type': eth_type,
            'payload': data[14:]
        }

    def parse_ip_header(self, data):
        """Parse IP header"""
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        
        version = ip_header[0] >> 4
        header_length = (ip_header[0] & 0xF) * 4
        ttl = ip_header[5]
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        
        return {
            'version': version,
            'header_length': header_length,
            'ttl': ttl,
            'protocol': protocol,
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'payload': data[header_length:]
        }

    def parse_tcp_header(self, data):
        """Parse TCP header"""
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
        
        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        sequence = tcp_header[2]
        acknowledgment = tcp_header[3]
        flags = tcp_header[5]
        
        # Extract flags
        flag_urg = (flags & 32) >> 5
        flag_ack = (flags & 16) >> 4
        flag_psh = (flags & 8) >> 3
        flag_rst = (flags & 4) >> 2
        flag_syn = (flags & 2) >> 1
        flag_fin = flags & 1
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'sequence': sequence,
            'acknowledgment': acknowledgment,
            'flags': {
                'URG': flag_urg,
                'ACK': flag_ack,
                'PSH': flag_psh,
                'RST': flag_rst,
                'SYN': flag_syn,
                'FIN': flag_fin
            },
            'payload': data[20:]
        }

    def parse_udp_header(self, data):
        """Parse UDP header"""
        udp_header = struct.unpack('!HHHH', data[:8])
        
        src_port = udp_header[0]
        dest_port = udp_header[1]
        length = udp_header[2]
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'length': length,
            'payload': data[8:]
        }

    def parse_icmp_header(self, data):
        """Parse ICMP header"""
        icmp_header = struct.unpack('!BBH', data[:4])
        
        icmp_type = icmp_header[0]
        code = icmp_header[1]
        checksum = icmp_header[2]
        
        return {
            'type': icmp_type,
            'code': code,
            'checksum': checksum,
            'payload': data[4:]
        }

    def get_protocol_name(self, protocol_num):
        """Get protocol name from number"""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        return protocols.get(protocol_num, f'Other({protocol_num})')

    def format_payload(self, data, max_lines=6):
        """Format payload data for display"""
        if not data:
            return f"{Colors.WARNING}No payload{Colors.ENDC}"
        
        # Show hex and ASCII representation
        lines = []
        for i in range(0, min(len(data), max_lines * 16), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f'{i:08x}: {hex_part:<48} {ascii_part}')
        
        if len(data) > max_lines * 16:
            lines.append(f'... ({len(data) - max_lines * 16} more bytes)')
        
        return '\n'.join(lines)

    def display_packet_info(self, packet_data):
        """Display formatted packet information"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        print(f"\n{Colors.OKCYAN}{'🟦'*40}{Colors.ENDC}")
        print(f"{Colors.BOLD}Packet #{self.packet_count} - {timestamp}{Colors.ENDC}")

        # Parse based on platform
        if sys.platform.startswith('win'):
            # Windows - starts with IP header
            ip_info = self.parse_ip_header(packet_data)
        else:
            # Linux - starts with Ethernet header
            eth_info = self.parse_ethernet_header(packet_data)
            print(f"{Colors.OKBLUE}Ethernet: {eth_info['src_mac']} ➡️ {eth_info['dest_mac']} | Type: 0x{eth_info['type']:04x}{Colors.ENDC}")
            
            if eth_info['type'] == 0x0800:  # IPv4
                ip_info = self.parse_ip_header(eth_info['payload'])
            else:
                print(f"{Colors.WARNING}Non-IPv4 packet (Type: 0x{eth_info['type']:04x}){Colors.ENDC}")
                return

        proto = self.get_protocol_name(ip_info['protocol'])
        print(f"{Colors.OKGREEN}IP: {ip_info['src_ip']} ➡️ {ip_info['dest_ip']} | Proto: {proto} | TTL: {ip_info['ttl']}{Colors.ENDC}")

        # Update stats
        if proto in self.stats:
            self.stats[proto] += 1
        else:
            self.stats['Other'] += 1

        # Parse transport layer
        if ip_info['protocol'] == 6:  # TCP
            tcp_info = self.parse_tcp_header(ip_info['payload'])
            print(f"{Colors.BOLD}TCP: {tcp_info['src_port']} ➡️ {tcp_info['dest_port']} | Seq: {tcp_info['sequence']} | Ack: {tcp_info['acknowledgment']}{Colors.ENDC}")
            active_flags = [flag for flag, value in tcp_info['flags'].items() if value]
            print(f"Flags: {', '.join(active_flags) if active_flags else 'None'}")
            if tcp_info['payload']:
                print(f"{Colors.OKCYAN}TCP Payload ({len(tcp_info['payload'])} bytes):{Colors.ENDC}")
                print(self.format_payload(tcp_info['payload']))
            src_port, dest_port = tcp_info['src_port'], tcp_info['dest_port']
        elif ip_info['protocol'] == 17:  # UDP
            udp_info = self.parse_udp_header(ip_info['payload'])
            print(f"{Colors.BOLD}UDP: {udp_info['src_port']} ➡️ {udp_info['dest_port']} | Length: {udp_info['length']}{Colors.ENDC}")
            if udp_info['payload']:
                print(f"{Colors.OKCYAN}UDP Payload ({len(udp_info['payload'])} bytes):{Colors.ENDC}")
                print(self.format_payload(udp_info['payload']))
            src_port, dest_port = udp_info['src_port'], udp_info['dest_port']
        elif ip_info['protocol'] == 1:  # ICMP
            icmp_info = self.parse_icmp_header(ip_info['payload'])
            print(f"{Colors.BOLD}ICMP: Type {icmp_info['type']} | Code {icmp_info['code']} | Checksum: 0x{icmp_info['checksum']:04x}{Colors.ENDC}")
            if icmp_info['payload']:
                print(f"{Colors.OKCYAN}ICMP Payload ({len(icmp_info['payload'])} bytes):{Colors.ENDC}")
                print(self.format_payload(icmp_info['payload']))
            src_port, dest_port = '', ''
        else:
            print(f"{Colors.WARNING}Unknown protocol: {ip_info['protocol']}{Colors.ENDC}")
            src_port, dest_port = '', ''

        # Optional logging
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(f"{timestamp},{proto},{ip_info['src_ip']},{ip_info['dest_ip']},{src_port},{dest_port},{len(packet_data)}\n")

    def should_capture_packet(self, packet_data):
        """Determine if packet should be captured based on filters"""
        if not self.protocol_filter:
            return True
        
        try:
            if sys.platform.startswith('win'):
                ip_info = self.parse_ip_header(packet_data)
            else:
                eth_info = self.parse_ethernet_header(packet_data)
                if eth_info['type'] != 0x0800:  # Not IPv4
                    return False
                ip_info = self.parse_ip_header(eth_info['payload'])
            
            protocol_name = self.get_protocol_name(ip_info['protocol']).lower()
            return protocol_name.startswith(self.protocol_filter.lower())
        except Exception:
            return False

    def print_stats(self):
        """Print live packet statistics"""
        print(f"\n{Colors.BOLD}Live Packet Stats:{Colors.ENDC}")
        for proto, count in self.stats.items():
            color = Colors.OKGREEN if proto == 'TCP' else Colors.OKBLUE if proto == 'UDP' else Colors.WARNING if proto == 'ICMP' else Colors.FAIL
            print(f"{color}{proto}: {count}{Colors.ENDC}", end=' | ')
        print()

    def start_capture(self):
        """Start packet capture"""
        print_banner()
        print(f"{Colors.BOLD}Protocol filter:{Colors.ENDC} {self.protocol_filter or 'All'}")
        print(f"{Colors.BOLD}Packet count limit:{Colors.ENDC} {self.count or 'Unlimited'}")
        if self.log_file:
            print(f"{Colors.BOLD}Logging to:{Colors.ENDC} {self.log_file}")
        print(f"{Colors.WARNING}Press Ctrl+C to stop{Colors.ENDC}\n")

        sock = self.create_socket()
        try:
            while True:
                if self.count and self.packet_count >= self.count:
                    break
                packet_data, addr = sock.recvfrom(65535)
                if self.should_capture_packet(packet_data):
                    self.packet_count += 1
                    self.display_packet_info(packet_data)
                    self.print_stats()
        except KeyboardInterrupt:
            print(f"\n\n{Colors.OKGREEN}Capture stopped. Total packets captured: {self.packet_count}{Colors.ENDC}")
            self.print_stats()
        except Exception as e:
            print(f"{Colors.FAIL}Error during capture: {e}{Colors.ENDC}")
        finally:
            sock.close()

def main():
    parser = argparse.ArgumentParser(description='CodeAlpha Network Packet Sniffer')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-p', '--protocol', choices=['tcp', 'udp', 'icmp'], help='Filter by protocol')
    parser.add_argument('-i', '--interface', help='Network interface (Linux only)')
    parser.add_argument('-l', '--log', help='Log captured packets to CSV file')
    args = parser.parse_args()

    print_banner()
    print(f"{Colors.WARNING}WARNING: This tool is for educational purposes only.")
    print("Ensure you have permission to monitor network traffic.")
    print("Use responsibly and in accordance with local laws.{Colors.ENDC}\n")

    if not args.interface and not sys.platform.startswith('win'):
        print(f"{Colors.OKCYAN}Available interfaces:{Colors.ENDC} {', '.join(list_interfaces())}")
        print(f"{Colors.WARNING}Tip: Use -i <interface> to specify one!{Colors.ENDC}\n")

    sniffer = PacketSniffer(
        interface=args.interface,
        count=args.count,
        protocol_filter=args.protocol,
        log_file=args.log
    )
    sniffer.start_capture()

if __name__ == "__main__":
    main()
