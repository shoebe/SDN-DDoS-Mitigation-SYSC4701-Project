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
from mininet.link import TCLink

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
            ips = [""] * (NUM_HOSTS_PER_SWITCH + 1)
            macs = [""] * (NUM_HOSTS_PER_SWITCH + 1)
            ips[0] = switch_ip
            macs[0] = switch_mac
            for i in range(1, NUM_HOSTS_PER_SWITCH + 1):
                ips[i] = f"10.0.{s_ind}.{i}"
                macs[i] = f"00:0{s_ind}:00:00:00:0{i}"
            for i in range(1, NUM_HOSTS_PER_SWITCH + 1):
                h = self.addHost(
                    f"h{NUM_HOSTS_PER_SWITCH * (s_ind-1) + i}",
                    ip=f"{ips[i]}/24",
                    defaultRoute=f"via {switch_ip}",
                    mac=macs[i],
                    arp=zip(ips, macs),
                )
                # 1Mbps rate from host to switch
                self.addLink(h, s, port2=i, bw=0.1, delay="50ms")

            self.addLink(s, parent_switch)

        s_ind = NUM_SWITCHES + 1
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
        # 3Mbps
        self.addLink(server, server_switch, bw=0.3, delay="50ms")
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
        # print([a for a in self.params["arp"]])
        for ip, mac in self.params["arp"]:
            self.setARP(ip=ip, mac=mac)
        return r


class CoolCLI(CLI):
    def do_ddos(self, line):
        args = line.split()
        ip = args[0]
        if ip in self.mn:
            ip = self.mn[ip].defaultIntf().updateIP()

        hosts = args[1:]
        for host_name in hosts:
            host = self.mn.getNodeByName(host_name)
            host.sendCmd(f"python3 packet_flood_ip_spoofing.py spoof {ip}")

    def do_stopddos(self, line):
        hosts = line.split()

        for host_name in hosts:
            host = self.mn.getNodeByName(host_name)
            host.sendInt()


controller = RemoteController("controller", port=6653)

net = Mininet(
    topo=CoolTopology(),
    host=CoolHost,
    switch=OVSSwitch,
    link=TCLink,
    build=False,
    waitConnected=True,
    autoSetMacs=True,
    controller=RemoteController,
)
net.addController(controller)
net.build()

net.start()

CoolCLI(net)
# net.hosts[0].cmd()

net.stop()
