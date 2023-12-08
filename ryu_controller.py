"""
Written by Sebastien Marleau and Prianna Rahman
for Carleton University's SYSC4701 "Communications System Lab" course
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, icmp
from ryu.lib.packet import ether_types
from ryu.lib import hub
import os

class CoolSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CoolSwitch, self).__init__(*args, **kwargs)
        self.icmp_request = {}
        self.icmp_reply = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        # actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)] # packets will be forwarded to controller
        actions = []  # packets dropped
        self.add_flow(datapath, 0, match, actions)

        # Add entries to table 0 (checked before table 1)
        # table-miss, goto table 1
        # match = parser.OFPMatch()
        # self.add_goto_table(datapath, 0, match, add_to_table_id=0, goto_table_id=1)

        # ASSUME tree topology with fanout = 3, depth = 2
        switch_num = datapath.id  # 1 s1, 2 for s2, 20 for s20
        if switch_num == 20:  # s20 (parent switch)
            for port_num in range(1, 4 + 1):
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=f"10.0.{port_num}.0/24",
                )
                actions = [parser.OFPActionOutput(port_num)]
                self.add_flow(datapath, 1, match, actions)
            return

        num_hosts = 3
        if switch_num == 4:
            num_hosts = 1

        for port_num in range(1, num_hosts + 1):
            addr = f"10.0.{switch_num}.{port_num}"
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=addr,
            )
            print(f"00:0{switch_num}:00:00:00:0{port_num}")
            actions = [
                parser.OFPActionSetField(
                    eth_src=f"00:0{switch_num}:00:00:00:00",
                ),
                parser.OFPActionSetField(
                    eth_dst=f"00:0{switch_num}:00:00:00:0{port_num}",
                ),
                parser.OFPActionOutput(port_num),
            ]
            if switch_num == 4 and "DDOS_MITIGATION" in os.environ:
                actions.append(parser.OFPActionOutput(ofproto.OFPP_CONTROLLER))
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch()
            if "BCP38_ENABLED" in os.environ:
                match = parser.OFPMatch(
                    ipv4_src=addr,
                    eth_type=ether_types.ETH_TYPE_IP,
                )
            actions = [parser.OFPActionOutput(num_hosts + 1)]
            if switch_num == 4 and "DDOS_MITIGATION" in os.environ:
                actions.append(parser.OFPActionOutput(ofproto.OFPP_CONTROLLER))
            self.add_flow(datapath, 1, match, actions)

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        table_id=0,
        buffer_id=None,
        idle_timeout=0,
    ):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                table_id=table_id,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                table_id=table_id,
            )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            pass
        
        if "DDOS_MITIGATION" not in os.environ:
            return

        # extract info
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser

        # extract ethernet, ip, and icmp info
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip = pkt.get_protocols(ipv4.ipv4)[0]
        icmp_info = pkt.get_protocols(icmp.icmp)[0]

        # When packet is ICMP request:
        # If request from specific host does not exist in icmp_request dictionary, add it to both the request and reply dictionaries and set values to 0
        # Update value of specific host (key) every time packet is ICMP request in icmp_request dictionary
        host_ip = ""
        if icmp_info.type == 8:
            if not ip.src in self.icmp_request:
                self.icmp_request[ip.src] = 0
                self.icmp_reply[ip.src] = 0
            self.icmp_request[ip.src] += 1
            host_ip = ip.src

        # When packet is ICMP reply:
        # If reply from specific host is not in the icmp_reply dictionary, add it to both the request and reply dictionaries and set values to 0
        # Update value of specific host (key) every time packet is ICMP reply in icmp_reply dictionary
        elif icmp_info.type == 0:
            if not ip.dst in self.icmp_reply:
                self.icmp_request[ip.dst] = 0
                self.icmp_reply[ip.dst] = 0
            self.icmp_reply[ip.dst] += 1
            host_ip = ip.dst

        # print out request and reply dictionaries
        self.logger.info(self.icmp_reply)
        self.logger.info(self.icmp_request)

        # If there are 4 more requests than replies, assume DDoS attack is occuring
        # Create flow to drop packets
        if self.icmp_request[host_ip] - self.icmp_reply[host_ip] >= 4:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst="10.0.4.1",
                ipv4_src=host_ip,
            )
            actions = []
            self.add_flow(datapath, 3, match, actions, idle_timeout=5)
