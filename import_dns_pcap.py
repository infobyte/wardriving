import os
from model.common import factory
from persistence.server import models
from scapy.all import DNSRR


def get_domain_resolutions(cap):
    for packet in cap:
        if packet.haslayer(DNSRR):
            layer = packet.getlayer(DNSRR)
            while True:
                layer = layer.payload
                if not isinstance(layer, DNSRR):
                    break
                if layer.type != 1:  # A
                    continue
                domain = layer.rrname
                if domain.endswith('.'):
                    # remove trailing dot
                    domain = domain[:-1]
                yield (domain, layer.rdata)

def main(workspace='', args=None, parser=None):

    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output from the pcapfile library.')
    parser.add_argument('pcap', help='Path to the PCAP file'),

    parsed_args = parser.parse_args(args)

    try:
        from scapy.all import PcapReader
    except ImportError:
        print 'capfile not found, please install it to use this plugin.' \
              ' You can do install it by executing pip2 install scapy in a shell.'
        return 1, None

    if not os.path.isfile(parsed_args.pcap):
        print "pcap file not found: " % parsed_args.pcap
        return 2, None

    pcap = PcapReader(parsed_args.pcap)
    for (domain, ip) in get_domain_resolutions(pcap):
        obj = factory.createModelObject(models.Host.class_signature, ip,
                                        workspace, parent_id=None)

        old = models.get_host(workspace, obj.getID())
        if old is None:
            models.create_host(workspace, obj)

        interface = factory.createModelObject(
            models.Interface.class_signature,
            '',
            workspace,
            # mac=bssid,
            ipv4_address=ip,
            ipv4_gateway='',
            ipv4_mask='',
            ipv4_dns='',
            ipv6_address='',
            ipv6_gateway='',
            ipv6_prefix='',
            ipv6_dns='',
            network_segment='',
            hostnames=[domain],
            parent_id=obj.getID())
        old = models.get_interface(workspace, obj.getID())
        if old is None:
            try:
                models.create_interface(workspace, interface)
            except:
                pass

    return 0, None
