#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""

import os
import time
from base64 import b64encode
from tempfile import NamedTemporaryFile
from collections import defaultdict

from scapy.all import (
    Dot11,
    Dot11Elt,
    Dot11Beacon,
    EAP,

)
from scapy.contrib.wpa_eapol import WPA_key
from scapy.layers.dot11 import Dot11

from persistence.server import models
from persistence.server.server_io_exceptions import ConflictInDatabase, CantCommunicateWithServerError, ResourceDoesNotExist
from model.common import factory

factory.register(models.Host)
factory.register(models.Vuln)
factory.register(models.Service)
factory.register(models.Interface)

__description__ = 'Import every AP found in a PCAP file'
__prettyname__ = 'Import Wardriving PCAP'

access_point_data = defaultdict(dict)
created_objs = defaultdict(set)


def save_objs(workspace_name):
    """
        This function uses a set to avoid hitting too much couchdb.
        Wifi packets usually are repeated, for example for beacons.
    :param workspace_name:
    :return:
    """
    order = ['Host', 'Interface', 'Service', 'Vulnerability']
    saved_ids = set()

    tmp = created_objs
    iterable = tmp.items()

    for type in order:
        for key, objs in iterable:
            if key == type:
                try:
                    if key == 'Host':
                        print('Total {0}: {1}'.format(key, len(objs)))
                        for obj in objs:
                            if obj.id in saved_ids:
                                models.update_host(workspace_name, obj)
                            else:
                                models.create_host(workspace_name, obj)
                            saved_ids.add(obj.id)
                    if key == 'Service':
                        print('Total {0}: {1}'.format(key, len(objs)))
                        for obj in objs:
                            if obj.id in saved_ids:
                                models.update_service(workspace_name, obj)
                            else:
                                models.create_service(workspace_name, obj)
                            saved_ids.add(obj.id)
                    if key == 'Vulnerability':
                        print('Total {0}: {1}'.format(key, len(objs)))
                        for obj in objs:
                            if obj.id in saved_ids:
                                models.update_vuln(workspace_name, obj)
                            else:
                                models.create_vuln(workspace_name, obj)
                    if key == 'Interface':
                        print('Total {0}: {1}'.format(key, len(objs)))
                        for obj in objs:
                            if obj.id in saved_ids:
                                models.update_interface(workspace_name, obj)
                            else:
                                models.create_interface(workspace_name, obj)
                            saved_ids.add(obj.id)
                except ConflictInDatabase as e:
                    print('Document already exists skipping.')
                    print(e)
                    continue
                except CantCommunicateWithServerError as e:
                    print('error')
                    print(e)
                except ResourceDoesNotExist as e:
                    print('Missing DB {0}'.format(workspace_name))
                    print(e)
                    continue
                except Exception as e:
                    print(e)


def extract_encryption(packet):
    elt = packet[Dot11Elt]
    while isinstance(elt, Dot11Elt):
        if elt.ID == 48:
            return 'wpa2'
        elif elt.ID == 221 and elt.info.startswith(b'\x00P\xf2\x01\x01\x00'):
            return 'wpa'
        elt = elt.payload
    capability = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                                {Dot11ProbeResp:%Dot11ProbeResp.cap%}").strip()
    if 'privacy' in capability:
        return 'wep'
    else:
        return 'open'


def process_wpa_key(workspace_name, packet):
    access_point = access_point_data[packet.addr3]
    if not access_point:
        return
    vuln = factory.createModelObject(
        models.Vuln.class_signature,
        'WPA Key for {0} found'.format(access_point.get('essid', '')),
        workspace_name,
        severity='info',
        status='open',
        confirmed='true',
        desc='WPA was found for the access point. Ensure you are using a secure password.',
        parent_id=access_point['host'].id
    )
    if vuln.id not in map(lambda vuln: vuln.id, created_objs['Vulnerability']):
        created_objs['Vulnerability'].add(vuln)


def process_beacon(workspace_name, packet):
    dot11_packet = packet[Dot11]
    essid = packet.info
    bssid = dot11_packet.addr3
    encryption = extract_encryption(packet)
    access_point = access_point_data[bssid]
    if not essid:
        essid = 'Hidden'
    access_point['essid'] = essid
    access_point['bssid'] = bssid
    access_point['encryption'] = encryption
    create_host_interface_and_vuln(workspace_name, access_point)


def create_host_interface_and_vuln(workspace_name, access_point):
    bssid = access_point['bssid']
    try:
        essid = access_point['essid'].encode('utf8')
    except Exception:
        return
    encryption = access_point['encryption']
    host = factory.createModelObject(
        models.Host.class_signature,
        essid,
        workspace_name=workspace_name,
        os=encryption,
        mac=bssid,
        parent_id=None)
    access_point['host'] = host
    if host.id not in map(lambda host: host.id, created_objs['Host']):
        created_objs['Host'].add(host)

    interface = factory.createModelObject(
        models.Interface.class_signature,
        '',
        workspace_name,
        mac=bssid,
        ipv4_address='',
        ipv4_gateway='',
        ipv4_mask='',
        ipv4_dns='',
        ipv6_address='',
        ipv6_gateway='',
        ipv6_prefix='',
        ipv6_dns='',
        network_segment='',
        parent_id=host.id)

    if interface.id not in map(lambda interface: interface.id, created_objs['Interface']):
        created_objs['Interface'].add(interface)
    access_point['interface'] = interface

    service = factory.createModelObject(
        models.Service.class_signature,
        encryption,
        workspace_name,
        protocol='802.11',
        status='open',
        description='Access point encryption',
        ports=[0],
        version='',
        service='open',
        parent_id=interface.id
        )
    if service.id not in map(lambda service: service.id, created_objs['Service']):
        created_objs['Service'].add(service)

    if encryption in ['open', 'wep']:
        vuln = factory.createModelObject(
            models.Vuln.class_signature,
            'Insecure WiFi {0} found'.format(essid),
            workspace_name,
            severity='critical',
            confirmed='true',
            status='open',
            desc='WiFi using {0} was found. Please change your router configuration.'.format(encryption),
            parent_id=host.id
        )
        if vuln.id not in map(lambda vuln: vuln.id, created_objs['Vulnerability']):
            created_objs['Vulnerability'].add(vuln)


def parse_wifi_pcaps(workspace_name, wifi_packets):
    for packet in wifi_packets:
        if packet.haslayer(Dot11):
            if packet.haslayer(Dot11Beacon):
                process_beacon(workspace_name, packet)
            if packet.haslayer(WPA_key):
                process_wpa_key(workspace_name, packet)

    return 0, None


def main(workspace_name='', args=None, parser=None):

    parser.add_argument('--dry-run', action='store_true', help='Do not touch the database. Only print the object ID')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output from the pcapfile library.')
    parser.add_argument('pcap', help='Path to the PCAP file'),
    parsed_args = parser.parse_args(args)

    try:
        from scapy.all import rdpcap
    except ImportError:
        print('capfile not found, please install it to use this plugin.' \
              ' You can do install it by executing pip2 install scapy in a shell.')
        return 1, None

    if not os.path.isfile(parsed_args.pcap):
        print("pcap file not found: " % parsed_args.pcap)
        return 2, None

    wifi_pcaps = rdpcap(parsed_args.pcap)
    workspace_name = parsed_args.workspace_name
    parse_wifi_pcaps(workspace_name, wifi_pcaps)

    if not parsed_args.dry_run:
        save_objs(workspace_name)