import scapy.all as scapy

interface = "eth0"

target_ip = "192.168.1.100"
target_port = 8080


delay_time = 300

sniffer = scapy.sniff(iface=interface, filter="tcp and dst %s and dst port %d" % (target_ip, target_port))

def delay_packet(packet):
    # Get the packet's timestamp
    timestamp = packet.time

    # Calculate the delay
    delay = delay_time

    # Set the packet's timestamp to the delayed time
    packet.time = timestamp + delay

    # Return the delayed packet
    return packet

sniffer.apply(delay_packet)

sniffer.start()
