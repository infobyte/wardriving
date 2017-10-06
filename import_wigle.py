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

try:
    from staticmap import StaticMap, CircleMarker
except ImportError:
    print('Please install staticmap with: pip install staticmap')


from persistence.server import models
from persistence.server.server import _save_to_couch
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


def draw_map():
    m = StaticMap(4000, 4000)
    for key, access_point in access_point_data.items():
        if not ('lat' in access_point and 'lng' in access_point):
            continue
        coords = (access_point['lat'], access_point['lng'])
        if access_point['lng'] - -34.611944444444 > 0.1:
            continue
        if access_point['lat'] - -58.364722222222 > 0.1:
            continue

        colors = {
            'open': 'red',
            'wep': 'red',
            'wpa': 'yellow',
            'wpa2': 'green'
        }
        marker_outline = CircleMarker(coords, colors[access_point['encryption']], 18)
        marker = CircleMarker(coords, '#0036FF', 12)

        m.add_marker(marker_outline)
        m.add_marker(marker)

    image = m.render(zoom=10)
    temp_file = NamedTemporaryFile(suffix='.png')
    image.save(temp_file.name)
    image.save('/Users/leonardolazzaro/workspace/faraday_codigo/test.png')
    return temp_file


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


def process_wigle_sqlite(workspace_name, wigle_filename):
    try:
        import sqlite3
    except ImportError:
        print('For using wigle import, sqlite3 is required. Please install it with: pip install sqlite3')
    conn = sqlite3.connect(wigle_filename)
    cursor = conn.execute('SELECT bssid, ssid, capabilities, bestlat, bestlon from network')
    for network in cursor:
        bssid = network[0]
        essid = network[1]
        capability = network[2].lower()
        lat = network[4]
        lng = network[3]
        access_point = access_point_data[bssid]
        if 'wpa' in capability and 'wpa2' not in capability:
            encryption = 'wpa'
        if 'wpa2' in capability:
            encryption = 'wpa2'
        if 'wep' in capability:
            encryption = 'wep'
        if 'open' in capability:
            encryption = 'open'

        access_point['essid'] = essid
        access_point['bssid'] = bssid
        access_point['encryption'] = encryption
        access_point['lat'] = lat
        access_point['lng'] = lng
        create_host_interface_and_vuln(workspace_name, access_point)
    map_file = draw_map()
    map_file.seek(0)
    now_timestamp = time.time()

    host = factory.createModelObject(
        models.Host.class_signature,
        'War driving results',
        workspace_name=workspace_name,
        parent_id=None)

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
    try:
        models.create_host(workspace_name, host)
    except ConflictInDatabase:
        pass
    try:
        models.create_interface(workspace_name, interface)
    except ConflictInDatabase:
        pass
    try:
        models.create_service(workspace_name, service)
    except ConflictInDatabase:
        pass

    name = 'Wardriving Map'
    description = 'See evidence for war driving map.'
    parent_id = host.id

    raw_obj = {
        "metadata": {"update_time": now_timestamp, "update_user": "", "update_action": 0, "creator": "UI Web",
                      "create_time": now_timestamp, "update_controller_action": "UI Web New", "owner": ""},
        "obj_id": "0c41d85f6dc71044518eea211bfbd12f2bad6f73", "owner": "",
        "parent": parent_id, "type": "Vulnerability", "ws": "wifi", "confirmed": True,
        "data": "", "desc": description, "easeofresolution": "",
        "impact": {"accountability": False, "availability": False, "confidentiality": False, "integrity": False},
        "name": name, "owned": False, "policyviolations": [], "refs": [], "resolution": "", "severity": "info",
        "status": "opened",
        "_attachments": {
             "map.png": {
             "content_type": "image/png",
            "data": b64encode(map_file.read())}},
        "protocol": "", "version": ""}
    obj = models.ModelBase(raw_obj, workspace_name)
    obj.setID(parent_id, name, description)
    vuln_id = obj.id
    raw_obj.update({"_id": vuln_id})
    try:
        _save_to_couch(workspace_name, vuln_id, **raw_obj)
    except ConflictInDatabase:
        pass
    map_file.close()


def main(workspace_name='', args=None, parser=None):

    parser.add_argument('--dry-run', action='store_true', help='Do not touch the database. Only print the object ID')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output from the pcapfile library.')
    parser.add_argument('wigle_sqlite', help='Wigle sqlite for gps coordinates'),

    parsed_args = parser.parse_args(args)

    if not os.path.isfile(parsed_args.wigle_sqlite):
        print("wigle sqlite file not found: " % parsed_args.wigle_sqlite)
        return 2, None

    process_wigle_sqlite(workspace_name, parsed_args.wigle_sqlite)

    if not parsed_args.dry_run:
        save_objs(workspace_name)