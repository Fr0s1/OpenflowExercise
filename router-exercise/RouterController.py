from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import arp, ethernet as eth, icmp, ipv4
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

# My code for OpenFlow Tutorial
# Reference: https://github.com/khooi8913/openflow-tutorial/blob/master/Router%20Exercise/RouterExercise.py#L90

class Router (object):
    def __init__ (self, connection):
        self.connection = connection

        connection.addListeners(self)
        
        # When an IP packet is sent from router to this controller, add mapping between MAC address and router/switch port
        self.mac_to_port = {}
        
        # Dictionary of packets waiting for ARP reply
        # When MAC address of packet's destination IP is not added in controller's arp table
        # add this packet to queue and wait for ARP reply then send packet when MAC addr is known
        self.arp_queue = {}

        # Static Route Table
        self.routing_table = {}
        self.routing_table['10.0.1.0/24'] = {'Port': 1, 'Gateway': '10.0.1.1'}
        self.routing_table['10.0.2.0/24'] = {'Port': 4, 'Gateway': '10.0.2.1'}
        self.routing_table['10.0.3.0/24'] = {'Port': 3, 'Gateway': '10.0.3.1'}
       
        # ARP cache of controller
        self.arp_table = {}
        self.arp_table['10.0.1.1'] = 'AA:BB:CC:DD:EE:01'
        self.arp_table['10.0.2.1'] = 'AA:BB:CC:DD:EE:02'
        self.arp_table['10.0.3.1'] = 'AA:BB:CC:DD:EE:03'


    def arp_handler (self, packet, packet_in):
        log.debug("ARP FRAME RECEIVED FROM %s" % packet_in.in_port)
        arp_packet = packet.payload

        if arp_packet.opcode == arp.REQUEST:
            arp_request_ip = str(arp_packet.protodst)
            log.debug("Handle ARP Request")
            log.debug(arp_request_ip)
            if arp_request_ip in self.arp_table:
                log.debug("Send Router interface MAC")
                arp_reply = arp()
                arp_reply.hwsrc = EthAddr(self.arp_table[arp_request_ip])
                arp_reply.hwdst = arp_packet.hwsrc
                arp_reply.protodst = arp_packet.protosrc
                arp_reply.protosrc = arp_packet.protodst
                arp_reply.opcode = arp.REPLY
                
                eth_frame = eth()
                eth_frame.payload = arp_reply
                eth_frame.dst = arp_packet.hwsrc
                eth_frame.src = EthAddr(self.arp_table[arp_request_ip])
                eth_frame.type = eth_frame.ARP_TYPE

                self.resend_packet(eth_frame, packet_in.in_port)
                log.debug("ARP REPLY SENT")

        elif arp_packet.opcode == arp.REPLY:
            log.debug("ARP reply received")
            arp_reply_srcip = str(arp_packet.protosrc)
            # Add new MAC address to controller's ARP table
            self.arp_table[arp_reply_srcip] = str(arp_packet.hwsrc)

            if arp_reply_srcip in self.arp_queue:                 
                eth_frame = eth()
                eth_frame.type = eth.IP_TYPE
                eth_frame.dst = arp_packet.hwdst 
                eth_frame.src = arp_packet.hwsrc
                eth_frame.payload = self.arp_queue[arp_reply_srcip]['ip_packet']
                out_port = self.arp_queue[arp_reply_srcip]['Port']
                self.resend_packet(eth_frame, out_port)
                
                msg = of.ofp_flow_mod()
                msg.match.set_nw_dst(self.arp_queue[arp_reply_srcip]['Destination Network'])
                msg.actions.append(of.ofp_action_dl_addr.src(eth_frame.src))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(eth_frame.dst))
                msg.actions.append(of.ofp_action_output(port = out_port))
                self.connection.send(msg)   

                self.arp_queue.pop(arp_reply_srcip)
    def icmp_handler (self, packet, packet_in):
        log.debug("Send router icmp reply")
        ip_payload = packet.payload 

        icmp_reply = icmp()
        icmp_reply.type = 0
        icmp_reply.payload = ip_payload.payload.payload
        
        ip_packet = ipv4()
        ip_packet.protocol = ipv4.ICMP_PROTOCOL
        ip_packet.srcip = ip_payload.dstip
        ip_packet.dstip = ip_payload.srcip
        ip_packet.payload = icmp_reply
        
        ether_frame = eth()
        ether_frame.src = packet.dst
        ether_frame.dst = packet.src
        ether_frame.payload = ip_packet
        ether_frame.type = eth.IP_TYPE
        
        self.resend_packet(ether_frame, packet_in.in_port)

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


    def _handle_PacketIn (self, event):
        packet = event.parsed

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp
        
        # Add entry to CAM table
        log.debug("Add entry: (MAC: {}, port: {}) to controller CAM table".format(str(packet.src), packet_in.in_port))
        self.mac_to_port[packet.src] = packet_in.in_port

        if packet.type == packet.ARP_TYPE:
            log.debug("Handle ARP request")
            self.arp_handler(packet, packet_in)
        elif packet.type == packet.IP_TYPE:
            ip_payload = packet.payload

            destination_ip = str(ip_payload.dstip)

            routable = False           
            destination_network = None
            out_port = None
            
            # Learn new IP and MAC address
            self.arp_table[str(ip_payload.srcip)] = str(packet.src)

            for network_addr in self.routing_table:
                if IPAddr(destination_ip).in_network(network_addr):
                    routable = True
                    destination_network = network_addr
                    out_port = self.routing_table[destination_network]['Port']
                    break;
            

            if routable:
                if self.routing_table[destination_network]['Gateway'] == destination_ip:
                    if ip_payload.protocol == ipv4.ICMP_PROTOCOL:
                        self.icmp_handler(packet, packet_in)

                # Check if controller already has MAC address of packet's destination IP
                if destination_ip in self.arp_table:
                    ether_frame = eth()
                    ether_frame.type = ether_frame.IP_TYPE

                    # Change packet source MAC address to Router interface's
                    ether_frame.src = EthAddr(self.arp_table[self.routing_table[destination_network]['Gateway']])
                    ether_frame.dst = EthAddr(self.arp_table[destination_ip])
                    ether_frame.payload = ip_payload
                    
                    self.resend_packet(ether_frame, out_port)
                else:
                    # If not, add current packet to buffer 
                    # then create ARP request from controller to host
                    self.arp_queue[destination_ip] = {'Destination Network': destination_network, 'Port': packet_in.in_port, 'ip_packet': ip_payload}

                    arp_request = arp()
                    arp_request.opcode = arp.REQUEST
                    arp_request.hwsrc = packet.src 
                    arp_request.hwdst = EthAddr("00:00:00:00:00:00")
                    arp_request.protosrc = ip_payload.srcip
                    arp_request.protodst = ip_payload.dstip
                    
                    eth_frame = eth()
                    eth_frame.dst = EthAddr("FF:FF:FF:FF:FF:FF")
                    eth_frame.payload = arp_request 
                    eth_frame.src = EthAddr(self.arp_table[self.routing_table[destination_network]['Gateway']])
                    eth_frame.type = eth.ARP_TYPE
                    self.resend_packet(eth_frame, out_port)
                    log.debug("ARP request for host {} sent".format(destination_ip))

            else:
                log.debug('PACKET IS NOT ROUTABLE!')
                icmp_reply = icmp()
                icmp_reply.type = 3
                icmp_reply.code = 1
                icmp_reply.payload = ip_payload.payload.payload
                
                ip_packet = ipv4()
                ip_packet.protocol = ipv4.ICMP_PROTOCOL
                ip_packet.srcip = ip_payload.dstip
                ip_packet.dstip = ip_payload.srcip
                ip_packet.payload = icmp_reply
                
                ether_frame = eth()
                ether_frame.src = packet.dst
                ether_frame.dst = packet.src
                ether_frame.payload = ip_packet
                ether_frame.type = eth.IP_TYPE
                
                self.resend_packet(ether_frame, packet_in.in_port)
                log.debug("ICMP DESTINATION UNREACHABLE SENT")

def launch():
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Router(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
