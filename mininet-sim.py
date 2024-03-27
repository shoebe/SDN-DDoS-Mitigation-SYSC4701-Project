#!/usr/bin/env python

"""
Written by Sebastien Marleau and Prianna Rahman
for Carleton University's SYSC4701 "Communications System Lab" course
"""

from mininet.net import Mininet
from mininet.node import Host, OVSSwitch, RemoteController
from mininet.topolib import TreeTopo
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.link import TCLink

setLogLevel("info")

from mininet.topo import Topo


class CoolTopology(Topo):
    def build(self):
        # See the topology
        parent_switch = self.addSwitch("s20")

        NUM_SWITCHES = 3
        NUM_HOSTS_PER_SWITCH = 3
        for s_ind in range(1, NUM_SWITCHES + 1):
            switch_ip = f"10.0.{s_ind}.100"
            switch_mac = f"00:0{s_ind}:00:00:00:00"
            # The switch doesn't really have an IP address or mac, 
            # we just make the hosts believe it does
            s = self.addSwitch(f"s{s_ind}")

            # index 0 is for the switch, 1-N is for h1-hN
            ips = [""] * (NUM_HOSTS_PER_SWITCH + 1)
            macs = [""] * (NUM_HOSTS_PER_SWITCH + 1)
            ips[0] = switch_ip
            macs[0] = switch_mac
            for i in range(1, NUM_HOSTS_PER_SWITCH + 1):
                ips[i] = f"10.0.{s_ind}.{i}"
                macs[i] = f"00:0{s_ind}:00:00:00:0{i}"
            
            for i in range(1, NUM_HOSTS_PER_SWITCH + 1):
                # for s1: h1-h3, for s2: h4-h6, etc.
                host_num = NUM_HOSTS_PER_SWITCH * (s_ind-1) + i
                h = self.addHost(
                    f"h{host_num}",
                    ip=f"{ips[i]}/24",
                    defaultRoute=f"via {switch_ip}",
                    mac=macs[i],
                    arp=zip(ips, macs),
                )
                # 0.1Mbps rate from host to switch
                self.addLink(h, s, port2=i, bw=0.1, delay="50ms")

            self.addLink(s, parent_switch)

        s_ind = NUM_SWITCHES + 1 #switch 4 connected to only the server
        switch_ip = f"10.0.{s_ind}.100"
        switch_mac = f"00:0{s_ind}:00:00:00:00"
        server_switch = self.addSwitch(f"s{s_ind}")
        server = self.addHost(
            "server",
            ip=f"10.0.{s_ind}.1/24",
            defaultRoute=f"via {switch_ip}",
            arp=[(switch_ip, switch_mac)],
            mac=f"00:0{s_ind}:00:00:00:01",
        )
        # 0.3Mbps
        self.addLink(server, server_switch, bw=0.3, delay="50ms")
        self.addLink(server_switch, parent_switch)


class CoolHost(Host):
    # This overrides the function in Host
    # adds arps configured in the topology to the hosts when net.build() is called
    def config(self, mac=None, ip=None, defaultRoute=None, lo="up", **_params):
        r = super().config(mac, ip, defaultRoute, lo, **_params)
        for ip, mac in self.params["arp"]:
            self.setARP(ip=ip, mac=mac)
        return r


class CoolCLI(CLI):
    # This adds a new command to the mininet CLI, 'ddos'
    def do_ddos(self, line):
        args = line.split()
        mode = args[0] # 'normal' or 'spoof'
        ip = args[1] # either a host name such as 'h1' or 'server', or an IP address
        if ip in self.mn:
            ip = self.mn[ip].defaultIntf().updateIP() # convert hostname to IP address

        hosts = args[2:]
        for host_name in hosts:
            host = self.mn.getNodeByName(host_name)
            if mode == "spoof":
                print(f"with src ip spoofing, flooding ip: {ip} from host {host_name}")
                host.sendCmd(f"python3 packet_flood.py spoof {ip}")
            elif mode == "normal":
                print(f"flooding ip: {ip} from host {host_name}")
                host_ip = host.defaultIntf().updateIP()
                host.sendCmd(f"python3 packet_flood.py {host_ip} {ip}")
            else:
                print("error! use 'spoof' or 'normal'")


controller = RemoteController("controller", port=6653)

net = Mininet(
    topo=CoolTopology(), # Topology from 'topology-diagram.png'
    host=CoolHost, # Sets arps on build
    switch=OVSSwitch,
    link=TCLink, # Allows the rate limiting and delay in links from the topology
    build=False,
    waitConnected=True, # Waits until all switches connect to the controller
    autoSetMacs=True,
    controller=RemoteController,
)
net.addController(controller)
net.build()

net.start()

CoolCLI(net)

net.stop()
