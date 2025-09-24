import scapy.all as scapy
import argparse

def get_args():
    parser = argparse.ArgumentParser(description="Ağdaki IP ve MAC adreslerini listele")
    parser.add_argument("-l", "--list", action="store_true", help="Ağdaki IP ve MAC adreslerini listele")
    parser.add_argument("-w", "--wizard", action="store_true", help="Wizard özelliğini aç")
    return parser.parse_args()

def scan_network(network):
    # ARP isteği göndererek ağdaki cihazları tarar
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    devices = []
    for element in answered_list:
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device_info)
    return devices

def print_result(devices):
    print("IP Adresi\t\tMAC Adresi")
    print("----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

def main():
    args = get_args()

    if args.list:
        # Ağdaki cihazları taramak için subnet IP adresini belirleyin
        # Burada örnek olarak 192.168.1.1/24 kullanılıyor. Kendi ağınıza göre değiştirebilirsiniz.
        network = "192.168.1.1/24"
        devices = scan_network(network)
        print_result(devices)

    if args.wizard:
        print("\nWizard aktif! Ağ taraması başlatılıyor...\n")
        # Burada taramayı başlatabilirsiniz veya başka özellikler ekleyebilirsiniz
        network = "192.168.1.1/24"
        devices = scan_network(network)
        print_result(devices)

if __name__ == "__main__":
    main()
