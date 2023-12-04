# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
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

icmp_request = {}
icmp_reply = {}

h1_request_counter = 0
h2_request_counter = 0
h3_request_counter = 0
h4_request_counter = 0
h5_request_counter = 0
h6_request_counter = 0
h7_request_counter = 0
h8_request_counter = 0
h9_request_counter = 0

h1_reply_counter = 0
h2_reply_counter = 0
h3_reply_counter = 0
h4_reply_counter = 0
h5_reply_counter = 0
h6_reply_counter = 0
h7_reply_counter = 0
h8_reply_counter = 0
h9_reply_counter = 0

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
        	if switch_num == 4:
            	actions.append(parser.OFPActionOutput(ofproto.OFPP_CONTROLLER))
        	self.add_flow(datapath, 2, match, actions)

        	match = parser.OFPMatch()
        	if "BCP38_ENABLED" in os.environ:
            	match = parser.OFPMatch(
                	ipv4_src=addr,
                	eth_type=ether_types.ETH_TYPE_IP,
            	)
        	actions = [parser.OFPActionOutput(num_hosts + 1)]
        	if switch_num == 4:
            	actions.append(parser.OFPActionOutput(ofproto.OFPP_CONTROLLER))
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
        	#self.logger.debug(
         	#   f"packet truncated: only {ev.msg.msg_len} of {ev.msg.total_len} bytes"
        	#)
        	pass
    	msg = ev.msg
    	datapath = msg.datapath
    	# ofproto = datapath.ofproto
    	# parser = datapath.ofproto_parser

    	pkt = packet.Packet(msg.data)
    	eth = pkt.get_protocols(ethernet.ethernet)[0]
    	ip = pkt.get_protocols(ipv4.ipv4)
    	if len(ip) > 0:
        	#self.logger.info(ip)
        	pass
       	 
    	icmp_info = pkt.get_protocols(icmp.icmp)[0]
    	if len(ip) > 0:
        	#self.logger.info(icmp_info)
        	pass
       	 
        # 0 or 8
    	self.logger.info(icmp_info.type)    
   	 
    	# IP source = ip.src
    	# IP destination = ip.dst

        # Request
        if(icmp_info.type == 8):
			if ip.src == "10.0.1.1":
				h1_request_counter += 1
				icmp_request.update({ip.src:h1_request_counter})
			elif ip.src == "10.0.1.2":
				h2_request_counter += 1
				icmp_request.update({ip.src:h2_request_counter})
			elif ip.src == "10.0.1.3":
				h3_request_counter += 1
				icmp_request.update({ip.src:h3_request_counter})
			elif ip.src == "10.0.1.4":
				h4_request_counter += 1
				icmp_request.update({ip.src:h4_request_counter})
			elif ip.src == "10.0.1.5":
				h5_request_counter += 1
				icmp_request.update({ip.src:h5_request_counter})
			elif ip.src == "10.0.1.6":
				h6_request_counter += 1
				icmp_request.update({ip.src:h6_request_counter})
			elif ip.src == "10.0.1.7":
				h7_request_counter += 1
				icmp_request.update({ip.src:h7_request_counter})
			elif ip.src == "10.0.1.8":
				h8_request_counter += 1
				icmp_request.update({ip.src:h8_request_counter})
			elif ip.src == "10.0.1.9":
				h9_request_counter += 1
				icmp_request.update({ip.src:h9_request_counter})
				
        # Response
        elif (icmp_info.type == 0):
			if ip.dst == "10.0.1.1":
				h1_reply_counter += 1
				icmp_reply.update({ip.src:h1_reply_counter})
			elif ip.dst == "10.0.1.2":
				h2_reply_counter += 1
				icmp_reply.update({ip.src:h2_reply_counter})
			elif ip.dst == "10.0.1.3":
				h3_reply_counter += 1
				icmp_reply.update({ip.src:h3_reply_counter})
			elif ip.dst == "10.0.1.4":
				h4_reply_counter += 1
				icmp_reply.update({ip.src:h4_reply_counter})
			elif ip.dst == "10.0.1.5":
				h5_reply_counter += 1
				icmp_reply.update({ip.src:h5_reply_counter})
			elif ip.dst == "10.0.1.6":
				h6_reply_counter += 1
				icmp_reply.update({ip.src:h6_reply_counter})
			elif ip.dst == "10.0.1.7":
				h7_reply_counter += 1
				icmp_reply.update({ip.src:h7_reply_counter})
			elif ip.dst == "10.0.1.8":
				h8_reply_counter += 1
				icmp_reply.update({ip.src:h8_reply_counter})
			elif ip.dst == "10.0.1.9":
				h9_reply_counter += 1
				icmp_reply.update({ip.src:h9_reply_counter})			
				
        if ((icmp_request.get("10.0.1.1") != 0 and icmp_reply.get("10.0.1.1") != 0) and (icmp_request.get("10.0.1.1") - icmp_reply.get("10.0.1.1") >= 4)):
			# add flow to drop packets
            print("DROPPED PACKETS - H1")
		
        if ((icmp_request.get("10.0.1.2") != 0 and icmp_reply.get("10.0.1.2") != 0) and (icmp_request.get("10.0.1.2") - icmp_reply.get("10.0.1.2") >= 4)):
			# add flow to drop packets
            print("DROPPED PACKETS - H2")

        if ((icmp_request.get("10.0.1.3") != 0 and icmp_reply.get("10.0.1.3") != 0) and (icmp_request.get("10.0.1.3") - icmp_reply.get("10.0.1.3") >= 4)):
			# add flow to drop packets
            print("DROPPED PACKETS - H3")		

        if ((icmp_request.get("10.0.1.4") != 0 and icmp_reply.get("10.0.1.4") != 0) and (icmp_request.get("10.0.1.4") - icmp_reply.get("10.0.1.4") >= 4)):
			# add flow to drop packets
            print("DROPPED PACKETS - H4")	            	

        if ((icmp_request.get("10.0.1.5") != 0 and icmp_reply.get("10.0.1.5") != 0) and (icmp_request.get("10.0.1.5") - icmp_reply.get("10.0.1.5") >= 4)):
			# add flow to drop packets
            print("DROPPED PACKETS - H5")	

        if ((icmp_request.get("10.0.1.6") != 0 and icmp_reply.get("10.0.1.6") != 0) and (icmp_request.get("10.0.1.6") - icmp_reply.get("10.0.1.6") >= 4)):
			# add flow to drop packets
            print("DROPPED PACKETS - H6")	 

        if ((icmp_request.get("10.0.1.7") != 0 and icmp_reply.get("10.0.1.7") != 0) and (icmp_request.get("10.0.1.7") - icmp_reply.get("10.0.1.7") >= 4)):
			# add flow to drop packets
            print("DROPPED PACKETS - H7")	 

        if ((icmp_request.get("10.0.1.8") != 0 and icmp_reply.get("10.0.1.8") != 0) and (icmp_request.get("10.0.1.8") - icmp_reply.get("10.0.1.8") >= 4)):
			# add flow to drop packets
            print("DROPPED PACKETS - H8")	 

        if ((icmp_request.get("10.0.1.9") != 0 and icmp_reply.get("10.0.1.9") != 0) and (icmp_request.get("10.0.1.9") - icmp_reply.get("10.0.1.9") >= 4)):
			# add flow to drop packets
            print("DROPPED PACKETS - H9")	                         			   
    
        
   	 
      		 

    	#print(f"packet in: {pkt} from datapath id: {datapath.id}")
