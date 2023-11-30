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
from ryu.lib.packet import ipv4, icmp
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
        # actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)] # packets will be forwarded to controller
        actions = []  # packets dropped
        self.add_flow(datapath, 0, match, actions)

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
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch()
            if "BCP38_ENABLED" in os.environ:
                match = parser.OFPMatch(
                    ipv4_src=addr,
                    eth_type=ether_types.ETH_TYPE_IP,
                )
            actions = [parser.OFPActionOutput(num_hosts + 1)]
            self.add_flow(datapath, 1, match, actions)

    def add_flow(self, datapath, priority, match, actions, table_id=0, buffer_id=None):
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
                table_id=table_id,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                table_id=table_id,
            )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug(
                f"packet truncated: only {ev.msg.msg_len} of {ev.msg.total_len} bytes"
            )
        msg = ev.msg
        datapath = msg.datapath
        # ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip = pkt.get_protocols(ipv4.ipv4)
        if len(ip) > 0:
            self.logger.info(ip)

        icmp_info = pkt.get_protocols(icmp.icmp)
        if len(ip) > 0:
            self.logger.info(icmp_info)

        print(f"packet in: {pkt} from datapath id: {datapath.id}")
