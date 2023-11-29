#!/usr/bin/env python

"""
Create a network where different switches are connected to
different controllers, by creating a custom Switch() subclass.
"""

from mininet.net import Mininet
from mininet.node import Host, OVSSwitch, RemoteController
from mininet.topolib import TreeTopo
from mininet.log import setLogLevel
from mininet.cli import CLI

setLogLevel("info")

from mininet.topo import Topo


class CoolTopology(Topo):
    def build(self):
        parent_switch = self.addSwitch("s20")

        NUM_SWITCHES = 3
        NUM_HOSTS_PER_SWITCH = 3
        for s_ind in range(1, NUM_SWITCHES + 1):
            switch_ip = f"10.0.{s_ind}.100"
            switch_mac = f"00:0{s_ind}:00:00:00:00"
            s = self.addSwitch(f"s{s_ind}")
            for i in range(1, NUM_HOSTS_PER_SWITCH + 1):
                h = self.addHost(
                    f"h{NUM_HOSTS_PER_SWITCH * (s_ind-1) + i}",
                    ip=f"10.0.{s_ind}.{i}/24",
                    defaultRoute=f"via {switch_ip}",
                    arp=(switch_ip, switch_mac),
                )
                # 1Mbps rate from host to switch
                self.addLink(h, s, port2=i, bw=1)

            self.addLink(parent_switch, s)

        s_ind = NUM_SWITCHES + 1
        switch_ip = f"10.0.{s_ind}.100"
        switch_mac = f"00:0{s_ind}:00:00:00:00"
        server_switch = self.addSwitch(f"s{s_ind}")
        server = self.addHost(
            "server",
            ip=f"10.0.{s_ind}.1/24",
            defaultRoute=f"via {switch_ip}",
            arp=(switch_ip, switch_mac),
        )
        # 3Mbps
        self.addLink(server, server_switch, bw=3)
        self.addLink(server_switch, parent_switch)


class CoolHost(Host):
    def config(self, mac=None, ip=None, defaultRoute=None, lo="up", **_params):
        """Configure Node according to (optional) parameters:
        mac: MAC address for default interface
        ip: IP address for default interface
        ifconfig: arbitrary interface configuration
        Subclasses should override this method and call
        the parent class's config(**params)"""
        # If we were overriding this method, we would call
        # the superclass config method here as follows:
        r = super().config(mac, ip, defaultRoute, lo, **_params)
        # self.setIP(ip=ip, prefixLen=self.params["ip_prefix"])
        self.setARP(ip=self.params["arp"][0], mac=self.params["arp"][1])
        return r


controller = RemoteController("controller", port=6653)

net = Mininet(
    topo=CoolTopology(),
    host=CoolHost,
    switch=OVSSwitch,
    build=False,
    waitConnected=False,
    autoSetMacs=True,
    controller=RemoteController,
)
net.addController(controller)
net.build()

net.start()
CLI(net)

net.stop()
