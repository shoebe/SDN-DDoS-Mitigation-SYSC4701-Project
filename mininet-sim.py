#!/usr/bin/env python

"""
Create a network where different switches are connected to
different controllers, by creating a custom Switch() subclass.
"""

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topolib import TreeTopo
from mininet.log import setLogLevel
from mininet.cli import CLI

setLogLevel( 'info' )

controller = RemoteController('controller', port=6653)

topo = TreeTopo( depth=2, fanout=3 )
net = Mininet( topo=topo, switch=OVSSwitch, build=False, waitConnected=False, autoSetMacs=True, autoStaticArp=True, controller=RemoteController)
net.addController(controller)
net.build()
net.start()
CLI( net )
net.stop()