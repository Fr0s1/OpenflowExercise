"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        h1 = self.addHost( 'h1', ip="10.0.1.2/24", defaultRoute = "via 10.0.1.1" )
        h2 = self.addHost( 'h2', ip = "10.0.1.3/24", defaultRoute = "via 10.0.1.1" )
        h3 = self.addHost( 'h3', ip="10.0.1.4/24", defaultRoute = "via 10.0.1.1" )

        h4 = self.addHost( 'h4', ip="10.0.2.2/24", defaultRoute = "via 10.0.2.1" )
        h5 = self.addHost( 'h5', ip="10.0.2.3/24", defaultRoute = "via 10.0.2.1" )
        h6 = self.addHost( 'h6', ip="10.0.2.4/24", defaultRoute = "via 10.0.2.1" )
        
        h7 = self.addHost( 'h7', ip="10.0.3.2/24", defaultRoute = "via 10.0.3.1" )
        h8 = self.addHost( 'h8', ip="10.0.3.3/24", defaultRoute = "via 10.0.3.1" )
        h9 = self.addHost( 'h9', ip="10.0.3.4/24", defaultRoute = "via 10.0.3.1" )

        # Add switches
        switch1 = self.addSwitch( 's1' )
        switch2 = self.addSwitch( 's2')
        switch3 = self.addSwitch( 's3') 

        # Add links
        self.addLink( switch1, h1) 
        self.addLink(switch1, h2)
        self.addLink(switch1, h3)

        self.addLink(switch2, h4)
        self.addLink(switch2, h5)
        self.addLink(switch2, h6)

        self.addLink(switch3, h7) 
        self.addLink(switch3, h8)
        self.addLink(switch3, h9)

        self.addLink(switch1, switch2)
        self.addLink(switch2, switch3)
        self.addLink(switch1, switch3)

topos = { 'mytopo': ( lambda: MyTopo() ) }
