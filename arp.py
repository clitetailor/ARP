# Programming language: Python3 (v3.5)
# OS used for this project: Linux (Ubuntu-Gnome)
# Dependency package:
#       netifaces (sudo apt-get install pip3 && sudo pip3 install netifaces)

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
        Reply 	= bytes.fromhex("0002")
	RarpRequest 	= bytes.fromhex("0003")
	RarpReply 	= bytes.fromhex("0004")
              
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

def BuildArpRequest(sender_mac_address, sender_ip_address, target_ip_address):
        
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

        packet += bytes.fromhex(sender_mac_address.replace(":", ""))
        packet += socket.inet_aton(sender_ip_address)
        packet += bytes.fromhex("ffffffffffff")
        packet += socket.inet_aton(target_ip_address)
        
        return packet

def DecodeArpReply(packet):
        structure = {}
        structure.update( {"oper": packet[20:22]} )
        structure.update( {"sha":  packet[22:28]} )
        structure.update( {"spa":  packet[28:32]} )
        structure.update( {"tha":  packet[32:38]} )
        structure.update( {"tpa":  packet[38:42]} )

        return structure

def BuildRarpRequest(sender_mac_address, broadcast_ip_address):
        
        #Ethernet Layer
        packet =  bytes.fromhex("ff ff ff ff ff ff")
        packet += bytes.fromhex( sender_mac_address.replace(":", "") )
        packet += Type.Arp

        #Arp Layer
        packet += HardwareType.Ethernet
        packet += ProtocolType.IPv4
        packet += HardwareSize.MAC
        packet += ProtocolSize.IPv4
        packet += OperationCode.RarpRequest

        packet += bytes.fromhex(sender_mac_address.replace(":", ""))
        packet += socket.inet_aton("0.0.0.0")
        packet += bytes.fromhex("ffffffffffff")
        packet += socket.inet_aton(broadcast_ip_address)
        
        return packet

def DecodeRarpReply(packet):
	
	return structure

def SendRawPacket(network_interface, packet):
        if network_interface in NetworkInterfaces():
                pass
        else:
                return
        
        sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        sender.bind((network_interface, 0))
        
        sender.send(packet)
        return

def ReceivePackets():
        receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        receiver.bind((network_interface, 0))
        
        packets = receiver.recvfrom(2048)

        return packets

def SendArp(target_ip_address):

        # Loop for network interface:
        if NetworkInterfaces() is None:
                return
        for interface in NetworkInterfaces():
                
                # Loop for mac address:
                if InterfaceMacAddresses(interface) is None or interface[0:2] == 'lo':
                        continue
                for mac in InterfaceMacAddresses(interface):
                        
                        # Loop for ip address:
                        if InterfaceIpAddresses(interface) is None:
                                continue
                        for ip in InterfaceIpAddresses(interface):
                                if ip is None:
                                        continue
                                # Send an ARP request packet
                                packet = CreateArpPacket(mac, ip, target_ip_address)
                                print("Interface {0}:".format(interface))
                                SendRawPacket(interface, packet)

                                # Receive an ARP reply packet
                                packets = ReceivePackets(interface)

                                # Loop for ARP packet:
                                for packet in packets:
                                        try:
                                                if packet[12:14] == b'0806':
                                                        
                                                        # Decode ARP reply packet
                                                        ethernet_header = packet[0:14]
                                                        ethernet_detail = struct.unpack("!6s6s2s", ethernet_header)

                                                        arp_header = packet[14:42]
                                                        arp_detail = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

                                                        print ("****************_ETHERNET_FRAME_****************")
                                                        print ("Dest MAC:        ", binascii.hexlify(ethernet_detail[0]))
                                                        print ("Source MAC:      ", binascii.hexlify(ethernet_detail[1]))
                                                        print ("Type:            ", binascii.hexlify(ethernet_detail[2]))
                                                        print ("************************************************")
                                                        print ("******************_ARP_HEADER_******************")
                                                        print ("Hardware type:   ", binascii.hexlify(arp_detail[0]))
                                                        print ("Protocol type:   ", binascii.hexlify(arp_detail[1]))
                                                        print ("Hardware size:   ", binascii.hexlify(arp_detail[2]))
                                                        print ("Protocol size:   ", binascii.hexlify(arp_detail[3]))
                                                        print ("Opcode:          ", binascii.hexlify(arp_detail[4]))
                                                        print ("Source MAC:      ", binascii.hexlify(arp_detail[5]))
                                                        print ("Source IP:       ", socket.inet_ntoa(arp_detail[6]))
                                                        print ("Dest MAC:        ", binascii.hexlify(arp_detail[7]))
                                                        print ("Dest IP:         ", socket.inet_ntoa(arp_detail[8]))
                                                        print ("*************************************************\n")
                                        except:
                                                pass
        return



# Main Program
if __name__ == "__main__":
        target_protocol_address = input("Target IP:")
        SendArp("192.168.1.1")
