from scapy.all import sniff, IP, TCP, UDP, Ether, Raw  # Added Raw import
import textwrap

def packet_handler(packet):
    
    summary = packet.summary()
    protocol = "Unknown"
    src_ip = dst_ip = "N/A"
    src_port = dst_port = "N/A"
    payload = ""

    
    if Ether in packet:
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst
    else:
        mac_src = mac_dst = "N/A"

    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        if protocol == 6:
            protocol = "TCP"
        elif protocol == 17:
            protocol = "UDP"
        else:
            protocol = f"IP-Protocol-{protocol}"

    
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    
    if packet.haslayer(Raw):  # Now properly recognized
        payload_bytes = packet[Raw].load
        
        # Handle payload display (first 100 bytes)
        try:
            # Attempt UTF-8 decoding
            payload_text = payload_bytes.decode('utf-8', errors='replace')
            # Show printable characters only
            payload = ''.join(
                c if 32 <= ord(c) < 127 or c in '\r\n\t' else f'\\x{ord(c):02x}' 
                for c in payload_text[:100]
            )
            if len(payload_bytes) > 100:
                payload += " [...]"
        except UnicodeDecodeError:
            # Format as hex dump
            hex_dump = ' '.join(f'{b:02x}' for b in payload_bytes[:20])
            if len(payload_bytes) > 20:
                hex_dump += " ..."
            payload = f"[Binary Data] {hex_dump}"

    
    print("\n" + "=" * 80)
    print(f"### Packet Summary: {summary}")
    print("-" * 80)
    print(f"Source MAC      : {mac_src}")
    print(f"Destination MAC : {mac_dst}")
    print(f"Source IP       : {src_ip}:{src_port}")
    print(f"Destination IP  : {dst_ip}:{dst_port}")
    print(f"Protocol        : {protocol}")
    
    if payload:
        print("\n--- Payload ---")
        for line in textwrap.wrap(payload, width=70):
            print(line)
    else:
        print("\n[No Payload]")

def main():
    print("Starting packet capture. Press Ctrl+C to stop...")
    try:
        
        sniff(prn=packet_handler, store=0, filter="ip")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

if __name__ == "__main__":
    main()