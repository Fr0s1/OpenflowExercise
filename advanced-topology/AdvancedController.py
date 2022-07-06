import re
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import arp, ethernet, icmp, ipv4
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

info_table = {}
# Destination Network is a dictionary with key is remote subnet CIDR, value is Next Hop
info_table[1] = {'Local Network': '10.0.1.0/24', 'Gateway': '10.0.1.1', 'Gateway Interface': 'AA:BB:CC:DD:EE:01', 'Destination Network': {'10.0.2.0/24': '10.0.2.1', '10.0.3.0/24': '10.0.3.1'}}

info_table[2] = {'Local Network': '10.0.2.0/24', 'Gateway': '10.0.2.1', 'Gateway Interface': 'AA:BB:CC:DD:EE:02', 'Destination Network': {'10.0.1.0/24': '10.0.1.1', '10.0.3.0/24': '10.0.3.1'}}

info_table[3] = {'Local Network': '10.0.3.0/24', 'Gateway': '10.0.3.1', 'Gateway Interface': 'AA:BB:CC:DD:EE:03', 'Destination Network': {'10.0.1.0/24': '10.0.1.1', '10.0.2.0/24': '10.0.2.1'}}

class Router (object):
    def __init__(self, connection):

        self.connection = connection

        connection.addListeners(self)
        
        # Keep track of source MAC address of packet coming to witch Router port
        self.mac_to_port = {}

        # Router unique id
        self.router_id = connection.dpid
        
        self.routing_table = info_table[self.router_id]

        # Router ARP cache table
        self.arp_table = {}

        # Packet with destination IP without known MAC address
        self.packet_queue = {}

    def resend_packet (self, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us.
        "packet_in" is the ofp_packet_in object the switch had sent to the
        controller due to a table-miss.
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in

        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)

        self.connection.send(msg)

    def arp_handler (self, packet, packet_in):
        arp_packet = packet.payload

        if arp_packet.opcode == arp.REQUEST:
            # Router needs to reply to ARP request in these 2 cases:
            # 1st: ask for own Router Interface 
            # 2nd: ask for host IP to MAC in LAN
            # else just drop ARP request packet

            # If received ARP request is destined to this router gateway interface MAC
            if arp_packet.protodst == IPAddr(self.routing_table['Gateway']):
                # Check if this ARP request to this router is sent by another router:
                if re.search(r'\.1$', str(arp_packet.protosrc)):
                    log.debug("Router %s receive ARP request from another router %s, learn that Router IP with MAC address %s" % (self.router_id, arp_packet.protosrc, arp_packet.hwsrc))
                    self.arp_table[str(arp_packet.protosrc)] = str(arp_packet.hwsrc)
                        
                gateway_interface_mac = self.routing_table['Gateway Interface']
                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = arp_packet.protodst
                arp_reply.protodst = arp_packet.protosrc
                arp_reply.hwsrc = EthAddr(gateway_interface_mac)
                arp_reply.hwdst = arp_packet.hwsrc

                ethernet_frame = ethernet()
                ethernet_frame.payload = arp_reply
                ethernet_frame.type = ethernet_frame.ARP_TYPE
                ethernet_frame.src = EthAddr(gateway_interface_mac)
                ethernet_frame.dst = arp_packet.hwsrc

                self.resend_packet(ethernet_frame, packet_in.in_port)
                log.debug("Router %s send ARP reply for IP %s with MAC address %s" % (self.router_id, arp_reply.protosrc, arp_reply.hwsrc))
            # Ask for MAC address of host IP in LAN
            elif arp_packet.protodst.in_network(self.routing_table['Local Network']):
                msg = of.ofp_packet_out()
                msg.data = packet
                # Notice: add in_port so that OFPP_FLOOD ignore that port
                # in_port here is the port which this ARP request packet coming to Router
                msg.in_port = packet_in.in_port
                msg.actions.append((of.ofp_action_output(port = of.OFPP_FLOOD)))
                self.connection.send(msg)

        elif arp_packet.opcode == arp.REPLY:
            arp_reply_srcip = str(arp_packet.protosrc)            
            arp_reply_dstip = str(arp_packet.protodst)
            log.debug("Router %s receives ARP reply for IP %s" % (self.router_id, arp_reply_srcip))

            out_port = packet_in.in_port
            
            self.arp_table[arp_reply_srcip] = str(arp_packet.hwsrc)
            self.mac_to_port[str(arp_packet.hwsrc)] = packet_in.in_port
            
            # Check if ARP reply for router's ARP Request
            # If not, send reply back to host need answer
            if arp_reply_dstip != self.routing_table['Gateway']:
                self.resend_packet(packet, self.mac_to_port[str(arp_packet.hwdst)])
            else:
                # If ARP reply for router, then check if there are any packets in buffer that wait to be sent
                if arp_reply_srcip in self.packet_queue:
                    for packet in self.packet_queue[arp_reply_srcip]['Packet']:
                        ethernet_frame = ethernet()
                        ethernet_frame.type = ethernet.IP_TYPE
                        ethernet_frame.src = EthAddr(self.routing_table['Gateway Interface'])
                        ethernet_frame.dst = arp_packet.hwsrc
                        ethernet_frame.payload = packet

                        self.resend_packet(ethernet_frame, self.mac_to_port[str(arp_packet.hwsrc)]) 
                    
                    self.packet_queue.pop(arp_reply_srcip)

    def icmp_handler(self, packet, packet_in):
        ip_packet = packet.payload

        icmp_reply = icmp()
        icmp_reply.payload = ip_packet.payload.payload
        icmp_reply.type = 0
        icmp_reply.code = 0

        ip_reply = ipv4()
        ip_reply.protocol = ipv4.ICMP_PROTOCOL
        ip_reply.payload = icmp_reply
        ip_reply.srcip = ip_packet.dstip
        ip_reply.dstip = ip_packet.srcip

        ethernet_frame = ethernet()
        ethernet_frame.type = ethernet.IP_TYPE
        ethernet_frame.src = packet.dst
        ethernet_frame.dst = packet.src
        ethernet_frame.payload = ip_reply
        
        self.resend_packet(ethernet_frame, packet_in.in_port)

    def _handle_PacketIn (self, event):
        packet = event.parsed

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp

        self.mac_to_port[str(packet.src)] = packet_in.in_port

        if packet.type == ethernet.ARP_TYPE:
            self.arp_handler(packet, packet_in)
        elif packet.type == ethernet.IP_TYPE:
            ip_packet = packet.payload
            destination_ip = str(ip_packet.dstip)
            source_ip = ip_packet.srcip

            # If incoming packet source IP coming from LAN connected to this router
            # then auto add this IP and MAC to ARP cache
            if source_ip.in_network(self.routing_table['Local Network']):
                self.arp_table[str(source_ip)] = str(packet.src)

            log.debug("Router %s receives packet with source IP: %s, destination IP: %s,  source MAC: %s, destination MAC: %s from switch port: %s" % (self.router_id, packet.payload.srcip, packet.payload.dstip, packet.src, packet.dst, packet_in.in_port))

            #self.arp_table[str(ip_packet.srcip)] = str(packet.src)

            # Check if ICMP request for Router
            if destination_ip == self.routing_table['Gateway'] and ip_packet.protocol == ipv4.ICMP_PROTOCOL and ip_packet.payload.type == 8:
                log.debug("Router %s: receive ICMP request for router with source IP %s, destination IP %s, source MAC %s, destination MAC %s" % (self.router_id, ip_packet.srcip, ip_packet.dstip, packet.src, packet.dst))
                self.icmp_handler(packet, packet_in)
                log.debug("Router %s has sent ICMP reply" % (self.router_id))
            else:
                # First, check destination IP is in this Router LAN
                if IPAddr(destination_ip).in_network(self.routing_table['Local Network']):
                    # Next, if the destination MAC of that host is not known, send ARP Request
                    if destination_ip not in self.arp_table:
                        log.debug("Router %s sent ARP for host with destination IP %s" % (self.router_id, destination_ip))

                        if destination_ip in self.packet_queue:
                            self.packet_queue[destination_ip]['Packet'].append[ip_packet]
                        else:
                            self.packet_queue[destination_ip] = {'Packet': [ip_packet], 'Port': packet_in.in_port }

                        arp_request = arp()
                        arp_request.opcode = arp.REQUEST
                        arp_request.hwsrc = EthAddr(self.routing_table['Gateway Interface'])
                        arp_request.hwdst = EthAddr("00:00:00:00:00:00") 
                        arp_request.protosrc = IPAddr(self.routing_table['Gateway'])
                        arp_request.protodst = ip_packet.dstip

                        ethernet_frame = ethernet()
                        ethernet_frame.type = ethernet.ARP_TYPE
                        ethernet_frame.payload = arp_request
                        ethernet_frame.src = EthAddr(self.routing_table['Gateway Interface'])
                        ethernet_frame.dst = EthAddr("FF:FF:FF:FF:FF:FF")

                        self.resend_packet(ethernet_frame, of.OFPP_FLOOD)  
                    else:
                        ethernet_frame = ethernet()
                        ethernet_frame.src = EthAddr(self.routing_table['Gateway Interface'])
                        ethernet_frame.dst = EthAddr(self.arp_table[destination_ip])
                        ethernet_frame.payload = ip_packet
                        ethernet_frame.type = ethernet.IP_TYPE

                        out_port = self.mac_to_port[self.arp_table[destination_ip]]
                        msg = of.ofp_flow_mod()
                        msg.match.dl_type = ethernet.IP_TYPE
                        #msg.match.set_nw_dst(IPAddr(self.routing_table['Local Network']))
                        msg.match.nw_dst = IPAddr(destination_ip)
                        msg.actions.append(of.ofp_action_output(port = out_port) )
                        msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.routing_table['Gateway Interface'])))
                        msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.arp_table[destination_ip])))

                        self.resend_packet(ethernet_frame, out_port)

                        #self.connection.send(msg)

                else:
                    # Check if destination IP is in network list known by controller
                    routable = False
                    destination_network = None
                    next_hop_ip = None
                    for network in self.routing_table['Destination Network']:
                        if IPAddr(destination_ip).in_network(network):
                            destination_network = network
                            next_hop_ip = self.routing_table['Destination Network'][network]
                            routable = True
                            break

                    if routable:
                        log.debug("Router %s: received IP Packet with destination IP %s not in router LAN! Will send to Next Hop %s" % (self.router_id, destination_ip, self.routing_table['Destination Network'][destination_network]))

                        if next_hop_ip not in self.arp_table:
                            log.debug("Router %s: MAC address of next hop IP is not known, send ARP from this router to get MAC address and put this packet in buffer!" % (self.router_id)) 
                            
                            # Check if there are any packets also waiting to sent to remote networks
                            if next_hop_ip in self.packet_queue:
                                self.packet_queue[next_hop_ip]['Packet'].append[ip_packet] # Add packet to list to be sent to next hop router
                            else:
                                self.packet_queue[next_hop_ip] = {'Packet': [ip_packet], 'Port': packet_in.in_port }

                            arp_request = arp()
                            arp_request.opcode = arp.REQUEST
                            arp_request.hwsrc = EthAddr(self.routing_table['Gateway Interface'])
                            arp_request.hwdst = EthAddr('00:00:00:00:00:00')
                            arp_request.protosrc = IPAddr(self.routing_table['Gateway'])
                            arp_request.protodst = IPAddr(next_hop_ip) 

                            ethernet_frame = ethernet()
                            ethernet_frame.type = ethernet.ARP_TYPE
                            ethernet_frame.src = EthAddr(self.routing_table['Gateway Interface'])
                            ethernet_frame.dst = EthAddr('FF:FF:FF:FF:FF:FF')
                            ethernet_frame.payload = arp_request
                            
                            self.resend_packet(ethernet_frame, of.OFPP_FLOOD)

                            log.debug("Router %s: send ARP request for next hop IP %s" % (self.router_id, self.routing_table['Destination Network'][network]))
                        else:
                            out_port = self.mac_to_port[self.arp_table[next_hop_ip]]
                            msg = of.ofp_flow_mod()
                            msg.match.dl_type = ethernet.IP_TYPE
                            msg.match.nw_dst = IPAddr.parse_cidr(destination_network)
                            msg.actions.append(of.ofp_action_output(port = out_port) )
                            msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.routing_table['Gateway Interface'])))
                            msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.arp_table[next_hop_ip])))

                            ethernet_frame = ethernet()
                            ethernet_frame.type = ethernet.IP_TYPE
                            ethernet_frame.src = EthAddr(self.routing_table['Gateway Interface'])
                            ethernet_frame.dst = EthAddr(self.arp_table[next_hop_ip]) 
                            ethernet_frame.payload = packet.payload
                            log.debug("Router %s frame src: %s, frame dst: %s" % (self.router_id, ethernet_frame.src, ethernet_frame.dst))
                            self.resend_packet(ethernet_frame, out_port) 
                            
                            self.connection.send(msg)
                    else:
                        icmp_packet = icmp()

def launch():
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Router(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
