# Programming language: Python3 (v3.5)
# OS used for this project: Linux (Ubuntu-Gnome)
# Dependency package: netifaces (sudo apt-get install pip3 && sudo pip3 install netifaces)

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
def SendArpPacket(packet):
        # Loop for network interface in 
        if NetworkInterfaces() is None:
                print("There is no interface!")
                return

        for network_interface in NetworkInterface():
                if network_interface[0:2] == 'lo':
                        continue
                elif InterfaceMacAddresses() is None:
                        continue
                else:
                        for 
        
        rawsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        rawsocket.bind((host_ip, 0))
        
        rawsocket.send(packet)
        return

def SendArpTo(target_ip_address):
        if NetworkInterfaces() is None:
                return
        for interface in NetworkInterfaces():
                if InterfaceMacAddresses(interface) is None or interface[0:2] == 'lo':
                        continue
                for mac in InterfaceMacAddresses(interface):
                        if InterfaceIpAddresses(interface) is None:
                                continue
                        for ip in InterfaceIpAddresses(interface):
                                if ip is None:
                                        continue
                                packet = CreateArpPacket(mac, ip, target_ip_address)
                                SendArpPacket(packet)
                                print("\t{0}: ARP packet was sended on this interface!".format(interface))
        return
                
                

def NetworkInterfaces():
        return ni.interfaces()

def InterfaceMacAddresses(network_interface):
        mac_addresses = []
        try:
                for mac_info in ni.ifaddresses(network_interface)[ni.AF_PACKET]:
                        mac_addresses.append(mac_info['addr'])
        except:
                pass
        return mac_addresses

def InterfaceIpAddresses(network_interface):
        ip_addresses = []
        try:
                for ip_info in ni.ifaddresses(network_interface)[ni.AF_INET]:
                        ip_addresses.append(ip_info['addr'])
        except:
                pass
        return ip_addresses

def CreateArpPacket(sender_mac_address, sender_ip_address, target_ip_address):
        
        #Ethernet Layer
        packet =  bytes.fromhex("ff ff ff ff ff ff")
        packet += bytes.fromhex( sender_mac_address.replace(":", "") )
        packet += Type.Arp

        #Arp Layer
        packet += HardwareType.Ethernet
        packet += ProtocolType.IPv4
        packet += HardwareAddressLength.MAC
        packet += ProtocolAddressLength.IPv4
        packet += OperationCode.Request

        #Data
        packet += bytes.fromhex(sender_mac_address.replace(":", ""))
        packet += socket.inet_aton(sender_ip_address)
        packet += bytes.fromhex("ffffffffffff")
        packet += socket.inet_aton(target_ip_address)
        
        return packet

def Encode(packet):
        structure = {}
        structure.update( {"oper": packet[20:22]} )
        structure.update( {"sha": packet[22:28]} )
        structure.update( {"spa": packet[28:32]} )
        structure.update( {"tha": packet[32:38]} )
        structure.update( {"tpa": packet[38:42]} )

        return structure

# Main Program
#
if __name__ == "__main__":
        print()
        print("Sending ARP:")
        print()
        SendArpTo("192.168.1.1")
        print()
