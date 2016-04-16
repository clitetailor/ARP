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


def SendArp(host_ip, host_mac_address, network_interface, gateway_ip):
	
	rawsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW)
	rawsocket = socket.connect((network_interface, 0))
	
	packet = CreateArpPacket(host_ip, host_mac_address, network_interface, gateway_ip)
	
	rawsocket.send(packet)
	return

def CreateArpPacket(host_ip, host_mac_address, network_interface, gateway_ip):
        packet = bytes(map(int, gateway_ip.split('.') )) + bytes(map(int, host_ip.split('.') )) + Type.Arp + HardwareType.Ethernet + ProtocolType.IPv4 + HardwareAddressLength.MAC + ProtocolAddressLength.IPv4 + OperationCode.Request + bytes.fromhex(host_mac_address.replace(":", "")) + bytes.fromhex(host_ip) + bytes.fromhex("ffffffffffff") + bytes.fromhex(map(int, gateway_ip.split('.') ))

        
        return packet

if __name__ == "__main__":
        print(CreateArpPacket("192.168.1.104", "28:c2:dd:5d:eb:3d", "wlp3s0", "192.168.1.1"))

