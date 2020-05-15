#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
import threading
from time import sleep
from scapy.all import *

import binascii
from sdnator_due import *


# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper


def writeTunnelRules(p4info_helper, ingress_sw, egress_sw, tunnel_id,
                     dst_eth_addr, dst_ip_addr, forward_port, egress_port):
    # table_entry = p4info_helper.buildTableEntry(
    #     table_name="MyIngress.ipv4_lpm",
    #     match_fields={
    #         "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
    #     },
    #     action_name="MyIngress.myTunnel_ingress",
    #     action_params={
    #         "dst_id": tunnel_id,
    #     })
    # ingress_sw.WriteTableEntry(table_entry)
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ether_exact",
        match_fields={
            "hdr.ethernet.dstAddr": dst_eth_addr
        },
        action_name="MyIngress.myTunnel_ingress",
        action_params={
            "dst_id": tunnel_id,
        })
    ingress_sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % ingress_sw.name


    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.myTunnel_exact",
        match_fields={
            "hdr.myTunnel.dst_id": tunnel_id
        },
        action_name="MyIngress.myTunnel_forward",
        action_params={
            "port": forward_port
        })
    ingress_sw.WriteTableEntry(table_entry)
    print "Installed transit tunnel rule on %s" % ingress_sw.name

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.myTunnel_exact",
        match_fields={
            "hdr.myTunnel.dst_id": tunnel_id
        },
        action_name="MyIngress.myTunnel_egress",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": egress_port
        })
    egress_sw.WriteTableEntry(table_entry)
    print "Installed egress tunnel rule on %s" % egress_sw.name

def dropByIP(p4info_helper, sw, ip, attr='srcAddr'):
    """
    Add drop rule to switch by ip

    Arguments:
        p4info_helper {P4InfoHelper}
        sw {Switch}
        ip {str}
    """
    print "Writing drop entry for %s, ip %s" % (sw.name, ip)
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.drop_table_ipv4",
        match_fields={
            "hdr.ipv4.%s" % attr: (str(ip), 32)
        },
        action_name="MyIngress.drop"
    )
    sw.WriteTableEntry(table_entry)


def dropByMac(p4info_helper, sw, mac_addr, attr='srcAddr'):
    """
    Add drop rule to switch by mac_addr

    Arguments:
        p4info_helper {P4InfoHelper}
        sw {Switch}
        mac_addr {str}
    """
    print "Writing drop entry for %s, mac_addr %s" % (sw.name, mac_addr)
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.drop_table_ether",
        match_fields={
            "hdr.ethernet.%s" % attr: str(mac_addr)
        },
        action_name="MyIngress.drop"
    )
    sw.WriteTableEntry(table_entry)


def listenAndEmitPackets(sw, p4info_helper, due):
    """
    Stream packets from grpcs

    Arguments:
        sw {Switch}
        fn {Function} -- callback
    """
    dataKey = "p4runtime::packet.%s" % sw.name
    for pkt in sw.StreamMessage('packet'):
        # handle IP and ARP only
        pkt = Ether(pkt.payload)
        due.write(dataKey, binascii.hexlify(str(pkt)), PUB_ONLY)

def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print "%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            )

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s2"
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s3"

        # Write the rules that tunnel traffic from h1 to h2
        writeTunnelRules(p4info_helper, ingress_sw=s1, egress_sw=s2, tunnel_id=100,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2",
                         forward_port=2, egress_port=1)

        # Write the rules that tunnel traffic from h2 to h1
        writeTunnelRules(p4info_helper, ingress_sw=s2, egress_sw=s1, tunnel_id=200,
                         dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1",
                         forward_port=2, egress_port=1)
        
        # Write the rules that tunnel traffic from h1 to h3
        writeTunnelRules(p4info_helper, ingress_sw=s1, egress_sw=s3, tunnel_id=300,
                         dst_eth_addr="08:00:00:00:03:33", dst_ip_addr="10.0.3.3",
                         forward_port=3, egress_port=1)

        # Write the rules that tunnel traffic from h3 to h1
        writeTunnelRules(p4info_helper, ingress_sw=s3, egress_sw=s1, tunnel_id=400,
                         dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1",
                         forward_port=2, egress_port=1)

        # Write the rules that tunnel traffic from h2 to h3
        writeTunnelRules(p4info_helper, ingress_sw=s2, egress_sw=s3, tunnel_id=500,
                         dst_eth_addr="08:00:00:00:03:33", dst_ip_addr="10.0.3.3",
                         forward_port=3, egress_port=1)
        
        # Write the rules that tunnel traffic from h3 to h2
        writeTunnelRules(p4info_helper, ingress_sw=s3, egress_sw=s2, tunnel_id=600,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2",
                         forward_port=3, egress_port=1)

        # TODO Uncomment the following two lines to read table entries from s1 and s2
        readTableRules(p4info_helper, s1)
        readTableRules(p4info_helper, s2)
        readTableRules(p4info_helper, s3)

        # init due
        due.set_pubsub({'driver': 'redis', 'host': 'localhost', 'port': 6379})
        due.set_db({'driver': 'mongo', 'host': 'localhost', 'port': 27017})
        # TODO: use the COORDINATOR flag to stop waiting
        due.init('P4RuntimeController', CONSUMER | PRODUCER | COORDINATOR)

        # listen for packet and send over to SDNator
        # NOTE: using s1 as example here
        emitter = threading.Thread(target=listenAndEmitPackets, args=(s1, p4info_helper, due))
        emitter.setDaemon(True)
        emitter.start()

        # listen for remote command
        o_attacker_ip = due.observe("kitsune::attacker_ip")
        dropped_ips = set()
        def drop_by_ip(ip):
            if ip in dropped_ips:
                print "%s should be dropped already!" % ip
            else:
                dropped_ips.add(ip)
                # NOTE: uncomment below for real blocking behavior 
                dropByIP(p4info_helper, s1, ip)
        o_attacker_ip.subscribe(on_next=lambda d: drop_by_ip(d[0]))

        o_attacker_mac = due.observe("kitsune::attacker_mac")
        dropped_macs = set()
        def drop_by_mac(mac):
            if mac in dropped_macs:
                print "%s should be dropped already!" % mac
            else:
                dropped_macs.add(mac)
                # NOTE: uncomment below for real blocking behavior
                dropByMac(p4info_helper, s1, mac)
        o_attacker_mac.subscribe(on_next=lambda d: drop_by_mac(d[0]))
        
        
        # keep the app running
        due.wait()

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()
    due.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
