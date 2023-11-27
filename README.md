# SDN-DDoS-Mitigation-SYSC4701-Project

```
sudo apt install python3-ryu
sudo apt install python3-scapy
```

Might have to:
```
sudo pip3 uninstall scapy
sudo apt install python3-scapy

sudo pip3 uninstall eventlet
sudo apt install python3-eventlet

sudo pip3 uninstall dnspython
sudo apt install python3-dnspython

sudo pip3 uninstall ryu
sudo apt install python3-ryu
```

To run:
```
./start.bash
```

Check flows:
```
dpctl dump flows
```


https://github.com/mininet/openflow-tutorial/wiki/Router-Exercise

https://opennetworking.org/wp-content/uploads/2014/10/openflow-switch-v1.5.1.pdf
https://ryu.readthedocs.io/en/latest/ofproto_v1_0_ref.html#controller-to-switch-messages
https://github.com/faucetsdn/ryu/blob/d6cda4f427ff8de82b94c58aa826824a106014c2/ryu/ofproto/ofproto_v1_3_parser.py
https://docs.openvswitch.org/en/latest/faq/openflow/

https://techhub.hpe.com/eginfolib/networking/docs/switches/5940/5200-1028b_openflow_cg/content/index.htm
