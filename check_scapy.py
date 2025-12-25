from scapy.all import get_if_list, conf

print(f"Scapy Version: {conf.version}")
print(f"Using Pcap: {conf.use_pcap}")
print("Interfaces found:")
try:
    iface_list = get_if_list()
    for i in iface_list:
        print(f" - {i}")
    print(f"Total Interfaces: {len(iface_list)}")
except Exception as e:
    print(f"Error listing interfaces: {e}")
