class RawSocket:
        def __init__(self):
                self.Socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))

        def Bind(self, network_interface):
                self.Socket.bind((network_interface, 0))

        def Send(self, packet_bytes):
                self.Socket.send(packet_bytes)

        def Receive(self):
                return self.Socket.recv()

class Packet:
        # Ethernet Layer
        def EthernetLayer(dest_mac_address, src_mac_address, protocol_type):
                ethernet_layer = b'0' * 14

                ethernet_layer[0:6]   = bytes.fromhex(dest_mac_address.replace(":", " "));
                ethernet_layer[6:12]  = bytes.fromhex(src_mac_address);
                ethernet_layer[12:14] = bytes.fromhex(protocol_type);

                return ethernet_layer
        
        # ARP Layer
        def ArpLayer(hardware_type = "0001", protocol_type = "0800", \
                     hardware_size = "06", protocol_size = "04", operation_code = "0001", \
                     sender_mac_address = None, sender_protocol_address = None, \
                     target_mac_address = "ff ff ff ff ff ff", target_protocol_address = None):
                
                arp_layer = b'0' * 28

                arp_layer[0:2]   = bytes.fromhex(hardware_type)
                arp_layer[2:4]   = bytes.fromhex(protocol_type)
                arp_layer[4:5]   = bytes.fromhex(hardware_size)
                arp_layer[5:6]   = bytes.fromhex(protocol_size)
                arp_layer[6:8]   = bytes.fromhex(operation_code)

                arp_layer[8:14]  = bytes.fromhex(sender_mac_address)
                arp_layer[14:18] = bytes.fromhex(sender_protocol_address)
                arp_layer[18:24] = bytes.fromhex(target_mac_address)
                arp_layer[24:28] = bytes.fromhex(target_protocol_address)

                return arp_layer

        def BuildArpRequest(sender_mac_address, sender_protocol_address, target_protocol_address):
                ethernet_layer = Packet.EthernetLayer("ff ff ff ff ff ff", sender_mac_address, "08 06")
                arp_layer = Packet.ArpLayer(sender_mac_address = sender_mac_address, sender_protocol_address = sender_protocol_address, target_protocol_address = target_protocol_address)

                packet = ethernet_layer + arp_layer
                return packet

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

        def GetBytes(self):
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

        def Decode(self, data):
                self.Opcode = packet[20:22]
                self.SenderMacAddress = packet[22:28]
                self.SenderIpAddress = packet[28:32]
                self.TargetMacAddress = packet[32:38]
                self.TargetIpAddress = packet[38:42]

