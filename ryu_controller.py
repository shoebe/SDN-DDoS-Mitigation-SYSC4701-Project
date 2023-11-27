# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from operator import attrgetter


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.lib import hub
import os

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        self.mac_to_port = {}      

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)] # packets will be forwarded to controller
        self.add_flow(datapath, 0, match, actions, table_id=1)

        # Add entries to table 0 (checked before table 1)
        # table-miss, goto table 1
        match = parser.OFPMatch()
        self.add_goto_table(datapath, 0, match, add_to_table_id=0, goto_table_id=1)

        # ASSUME tree topology with fanout = 3, depth = 2
        switch_num = datapath.id # 1 for s1, 2 for s2, etc.
        if switch_num == 1: # s1 does not drop packets based on IP
            return

        if "BCP38_ENABLED" in os.environ:
            # table-miss for IPv4 packets (packets that do not have the right IP)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
            actions = [] # no action, packets dropped
            self.add_flow(datapath, 1, match, actions, table_id=0)

            for i in range(1, 3+1):
                host_num = (switch_num-2) * 3 + i # 1,2,3 for s2; 4,5,6 for s3 ...
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=f"10.0.0.{host_num}", in_port=i)
                self.add_goto_table(datapath, 2, match, add_to_table_id=0, goto_table_id=1) # same as table-miss for non-IPv4

                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=f"10.0.0.{host_num}", in_port=4)
                self.add_goto_table(datapath, 2, match, add_to_table_id=0, goto_table_id=1) # same as table-miss for non-IPv4


    def add_goto_table(self, datapath, priority, match, add_to_table_id, goto_table_id):
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionGotoTable(goto_table_id)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, table_id=add_to_table_id)
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, table_id, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, table_id=table_id)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip = pkt.get_protocols(ipv4.ipv4)
        if len(ip) > 0:
            self.logger.info(ip)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        self.logger.info(f"learned mac address dpid: {dpid} src: {src}, dst: {dst} in_port: {in_port}")

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, table_id=1, buffer_id=msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 10, match, actions, table_id=1)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
