import socket

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


def SendArp(network_interface, packet):
    
    rawsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    rawsocket.bind((network_interface, 0))
    
    rawsocket.send(packet)
    return

def CreateArpPacket(host_ip, host_mac_address, network_interface, gateway_ip):
    #Ethernet Layer
    packet = bytes.fromhex("ff ff ff ff ff ff")
    packet = packet + bytes.fromhex( host_mac_address.replace(":", "") )
    packet = packet + Type.Arp
    #Arp Layer
    packet = packet + HardwareType.Ethernet
    packet = packet + ProtocolType.IPv4
    packet = packet + HardwareAddressLength.MAC
    packet = packet + ProtocolAddressLength.IPv4
    packet = packet + OperationCode.Request
    packet = packet + bytes.fromhex(host_mac_address.replace(":", ""))
    packet = packet + socket.inet_aton(host_ip)
    packet = packet + bytes.fromhex("ffffffffffff")
    packet = packet + socket.inet_aton(gateway_ip)
    
    
    return packet

if __name__ == "__main__":
    print(CreateArpPacket("192.168.1.101", "28:c2:dd:5d:eb:3d", "wlp3s0", "192.168.1.1"))

