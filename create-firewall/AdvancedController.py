from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import arp, ethernet as eth, icmp, ipv4
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

info_table = {}
info_table[1] = {'Local Network': '10.0.1.0/24', 'Gateway': '10.0.1.1', 'Gateway Interface': 'AA:BB:CC:DD:EE:01'}

info_table[2] = {'Local Network': '10.0.2.0/24', 'Gateway': '10.0.2.1', 'Gateway Interface': 'AA:BB:CC:DD:EE:02'}

class Router (object):
    def __init__(self, connection):

        self.connection = connection

        connection.addListeners(self)

        self.mac_to_port = {}

        # Router unique id
        self.router_id = connection.dpid
        
        self.routing_table = info_table[self.router_id]

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
            arp_reply = arp()
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc = arp_packet.protodst
            arp_reply.protodst = arp_packet.protosrc

            # Ask for router gateway interface
            if arp_packet.protodst == EthAddr(self.routing_table['Gateway']):
               arp_reply.hwsrc = EthAddr(self.routing_table['Gateway Interface'])
               arp_reply.hwdst = arp_packet.hwsrc

            eth_frame = eth()
            eth_frame.payload = arp_reply
            eth_frame.type = eth_frame.ARP_TYPE
            eth_frame.src = EthAddr(self.routing_table['Gateway Interface'])
            eth_frame.dst = arp_packet.hwsrc

            self.resend_packet(eth_frame, packet_in.in_port)


    def _handle_PacketIn (self, event):
        packet = event.parsed

        if not packet.parsed:
            log.warnign("Ignoring incomplete packet")
            return

        packet_in = event.ofp

        self.mac_to_port[str(packet.src)] = packet_in.in_port

        if packet.type == eth.ARP_TYPE:
            self.arp_handler(packet, packet_in)

def launch():
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Router(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
