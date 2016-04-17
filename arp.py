import socket
import netifaces as ni

# Enumerate
#
#
#
class Type:
	Arp = bytes.fromhex("0806")

class HardwareType:
    Ethernet = bytes.fromhex("0001")

class ProtocolType:
        IPv4 = bytes.fromhex("0800")

class HardwareAddressLength:
        MAC = bytes.fromhex("06")

class ProtocolAddressLength:
        IPv4 = bytes.fromhex("04")
        IPv6 = bytes.fromhex("06")

class OperationCode:
        Request = bytes.fromhex("0001")
        Reply = bytes.fromhex("0002")


# Methods
#
#
#
def SendArp(network_interface, packet):
        rawsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        rawsocket.bind((network_interface, 0))
        
        rawsocket.send(packet)
        return

def NetworkInterfaces():
        return ni.interfaces()

def InterfaceMacAddresses(network_interface):
        mac_addresses = []
        for mac_info in ni.ifaddresses(network_interface)[ni.AF_PACKET]:
                mac_addresses.append(mac_info['addr'])
        return mac_addresses

def InterfaceIpAddresses(network_interface):
        ip_addresses = []
        for ip_info in ni.ifaddresses(network_interface)[ni.AF_INET]:
                ip_addresses.append(ip_info['addr'])
        return ip_addresses

def CreateArpPacket(sender_mac_address, sender_ip_address, target_ip_address):
        
        #Ethernet Layer
        packet = bytes.fromhex("ff ff ff ff ff ff")
        packet = packet + bytes.fromhex( sender_mac_address.replace(":", "") )
        packet = packet + Type.Arp

        #Arp Layer
        packet = packet + HardwareType.Ethernet
        packet = packet + ProtocolType.IPv4
        packet = packet + HardwareAddressLength.MAC
        packet = packet + ProtocolAddressLength.IPv4
        packet = packet + OperationCode.Request

        #Data
        packet = packet + bytes.fromhex(sender_mac_address.replace(":", ""))
        packet = packet + socket.inet_aton(sender_ip_address)
        packet = packet + bytes.fromhex("ffffffffffff")
        packet = packet + socket.inet_aton(target_ip_address)
        
        return packet

# Main Program
#
if __name__ == "__main__":
        
	interface = NetworkInterfaces()[2]
	mac = InterfaceMacAddresses(interface)[0]
	ip = InterfaceIpAddresses(interface)[0]
	
	gateway = "192.168.1.1"

	packet = CreateArpPacket(mac, ip, gateway)
	SendArp(interface, packet)
