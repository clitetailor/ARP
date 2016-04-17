# Programming language: Python3 (v3.5)
# OS used for this project: Linux (Ubuntu-Gnome)
# Dependency package:
#       netifaces (sudo apt-get install pip3 && sudo pip3 install netifaces)
#       pep3124 (sudo 

import socket
import netifaces as ni
import struct
import binascii

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

class HardwareSize:
        MAC = bytes.fromhex("06")

class ProtocolSize:
        IPv4 = bytes.fromhex("04")
        IPv6 = bytes.fromhex("06")

class OperationCode:
        Request = bytes.fromhex("0001")
        Reply = bytes.fromhex("0002")

class RawSocket:
        def __init__(self):
                self.Socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

        def Bind(network_interface):
                self.Socket.bind((network_interface, 0))

        def Send(packet_bytes):
                self.Socket.send(packet_bytes)

        def Receive():
                return self.Socket.recv()

class ArpPacket:
        def __init__(self, sender_mac_address, sender_ip_address, target_ip_address):
                #Ethernet Layer
                self.Destination = bytes.fromhex("ff ff ff ff ff ff")
                self.Source = bytes.fromhex( sender_mac_address.replace(":", "") )
                self.Type = Type.Arp

                #Arp Layer
                self.HardwareSize = HardwareType.Ethernet
                self.ProtocolSize = ProtocolType.IPv4
                self.HardwareSize = HardwareSize.MAC
                self.ProtocolSize = ProtocolSize.IPv4
                self.OperationCode = OperationCode.Request

                #Data
                self.SenderMacAddress = bytes.fromhex(sender_mac_address.replace(":", ""))
                self.SenderIpAddress = socket.inet_aton(sender_ip_address)
                self.TargetMacAddress = bytes.fromhex("ffffffffffff")
                self.TargetIpAddress = socket.inet_aton(target_ip_address)

        def GetBytes():
                #Ethernet Layer
                data =  self.Destination
                data += self.Source
                data += self.Type

                #Arp Layer
                data += self.HardwareSize
                data += self.ProtocolSize
                data += self.HardwareSize
                data += self.ProtocolSize
                data += self.OperationCode

                #Data
                data += self.SenderMacAddress
                data += self.SenderIpAddress
                data += self.TargetMacAddress
                data += self.TargetIpAddress

                return data

        def Decode(data):
                self.Opcode = packet[20:22]
                self.SenderMacAddress = packet[22:28]
                self.SenderIpAddress = packet[28:32]
                self.TargetMacAddress = packet[32:38]
                self.TargetIpAddress = packet[38:42]

                
# Methods
#
#
#
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
        packet += HardwareSize.MAC
        packet += ProtocolSize.IPv4
        packet += OperationCode.Request

        #Data
        packet += bytes.fromhex(sender_mac_address.replace(":", ""))
        packet += socket.inet_aton(sender_ip_address)
        packet += bytes.fromhex("ffffffffffff")
        packet += socket.inet_aton(target_ip_address)
        
        return packet

def Decode(packet):
        structure = {}
        structure.update( {"oper": packet[20:22]} )
        structure.update( {"sha": packet[22:28]} )
        structure.update( {"spa": packet[28:32]} )
        structure.update( {"tha": packet[32:38]} )
        structure.update( {"tpa": packet[38:42]} )

        return structure

def SendRawPacket(network_interface, packet):
        if network_interface in NetworkInterfaces():
                pass
        else:
                return
        
        sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        sender.bind((network_interface, 0))
        
        sender.send(packet)

        packet = sender.recvfrom(2048)

        ethernet_header = packet[0][0:14]
        ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)

        arp_header = packet[0][14:42]
        arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

        print ("****************_ETHERNET_FRAME_****************")
        print ("Dest MAC:        ", binascii.hexlify(ethernet_detailed[0]))
        print ("Source MAC:      ", binascii.hexlify(ethernet_detailed[1]))
        print ("Type:            ", binascii.hexlify(ethernet_detailed[2]))
        print ("************************************************")
        print ("******************_ARP_HEADER_******************")
        print ("Hardware type:   ", binascii.hexlify(arp_detailed[0]))
        print ("Protocol type:   ", binascii.hexlify(arp_detailed[1]))
        print ("Hardware size:   ", binascii.hexlify(arp_detailed[2]))
        print ("Protocol size:   ", binascii.hexlify(arp_detailed[3]))
        print ("Opcode:          ", binascii.hexlify(arp_detailed[4]))
        print ("Source MAC:      ", binascii.hexlify(arp_detailed[5]))
        print ("Source IP:       ", socket.inet_ntoa(arp_detailed[6]))
        print ("Dest MAC:        ", binascii.hexlify(arp_detailed[7]))
        print ("Dest IP:         ", socket.inet_ntoa(arp_detailed[8]))
        print ("*************************************************\n")

def SendArp(target_ip_address):
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
                                print("Interface {0}:".format(interface))
                                SendRawPacket(interface, packet)
        return



# Main Program
#
if __name__ == "__main__":
        print()
        print("Sending ARP:")
        print()
        SendArp("192.168.1.1")
        print()
