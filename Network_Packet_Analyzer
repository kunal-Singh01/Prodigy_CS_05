import scapy.all as scapy
import netifaces

def get_interface_names():
    
    interfaces =netifaces.interfaces()
    return interfaces

def print_available_interfaces(interfaces):
    
    print("Available interfaces:")
    
    for i, interface in enumerate(interfaces, start=1):
        print(f"{i}. {interface}")

def packet_callback(packet):
    
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"\nPacket: {ip_src} -> {ip_dst}, Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print(f"TCP Port: {src_port} -> {dst_port}")

        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print(f"UDP Port: {src_port} -> {dst_port}")


interfaces =get_interface_names()


print_available_interfaces(interfaces)


try:
    selected_interface_index = int(input("Enter the number of the interface you wish to capture packets: "))
    selected_interface = interfaces[selected_interface_index - 1]
except (ValueError, IndexError):
    print("Invalid input. Please enter a valid interface number.")
    exit(1)

print(f"\nSelected interface: {selected_interface}")


scapy.sniff(iface=selected_interface, store=False, prn=packet_callback)
