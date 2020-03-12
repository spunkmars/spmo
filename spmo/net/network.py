# -*- coding:utf-8 -*-
import ipaddress
import sys


def format_str(vstr):
    if sys.version_info >= (3, 0, 0):
        return str(vstr)
    else:
        return unicode(vstr)


def spilit_ip_network(ip_network=None):
    net4 = ipaddress.ip_network(format_str(ip_network))
    return {'begin_ip': net4[1], 'end_ip': net4[-2], 'broadcast_ip': net4[-1], 'netmask': net4.netmask}


def prefixlen_to_netmask(prefixlen=None):
    return ipaddress.IPv4Network(format_str('0.0.0.0/%s' % prefixlen)).netmask


def netmask_to_prefixlen(netmask=None):
    return ipaddress.IPv4Network(format_str('0.0.0.0/%s' % netmask)).prefixlen


def get_ip_network(inter_ip=None, inter_ip_netmask=None, return_str=True):
    interface = ipaddress.IPv4Interface(format_str('%s/%s' % (inter_ip, inter_ip_netmask)))
    if return_str:
        return format_str(interface.network)
    else:
        return interface.network


def is_ip_in_network(ip=None, inter_ip=None, inter_ip_netmask=None):
    target_ip_object = ipaddress.IPv4Address(format_str(ip))
    ip_network_object = get_ip_network(inter_ip=inter_ip, inter_ip_netmask=inter_ip_netmask, return_str=False)
    if target_ip_object in ip_network_object:
        return True
    return False


def is_private_ip(ip=None):
    private = [
        ['127.0.0.0', '255.0.0.0'],
        ['192.168.0.0', '255.255.0.0'],
        ['172.16.0.0', '255.240.0.0'],
        ['10.0.0.0', '255.0.0.0']
    ]
    for p_netwrok in private:
        if is_ip_in_network(ip=ip, inter_ip=p_netwrok[0], inter_ip_netmask=p_netwrok[1]):
            return True
    return False


def is_ip_in_range2(begin_ip, mask, end_ip, target_ip):
    ip_range = "%s/%s" % (begin_ip, mask)
    begin_ip_object = ipaddress.IPv4Address(begin_ip)
    end_ip_object = ipaddress.IPv4Address(end_ip)
    target_ip_object = ipaddress.IPv4Address(target_ip)
    ip_network_object = get_ip_network(inter_ip=begin_ip, inter_ip_netmask=mask, return_str=False)
    if target_ip_object in ip_network_object and target_ip_object >= begin_ip_object and target_ip_object <= end_ip_object:
        return True
    else:
        return False
