# -*- coding:utf-8 -*-

import sys
import os
import re
import socket
# import tldextract

from dns import resolver, rdataclass, rdatatype

from spmo.common import Common
from spmo.common import DD
from spmo.net.http import Http
from spmo.net.http import parse_uri
from spmo.file.common import File
from spmo.data_serialize import DataSerialize
from spmo.datetime_s.common import convert_date_to_timestamp
from spmo.settings import CONF_DIRS


### curl  --referer https://www.internic.net/whois.html --user-agent 'Chrome/54.0 (Windows NT 10.0)' 'https://reports.internic.net/cgi/whois?whois_nic=sunteng.com&type=domain'


def split_text_to_list(text=''):
    a_lines = []
    for tag in ['\r\n', '\n', '\r']:
        a_lines = text.split(tag)
        if len(a_lines) > 5:
            break
    return a_lines


def load_whois_server_config(config_file=None):
    '''
    https://raw.githubusercontent.com/regru/php-whois/master/src/Phois/Whois/whois.servers.json
    :param config_file:
    :return:
    '''
    if config_file is None:
        config_file = os.path.join(CONF_DIRS, 'whois.servers.json')
    content = ''
    ds = DataSerialize()
    config_dict = {}
    if os.path.exists(config_file):
        fh = File()
        content = fh.read_file(rfile=config_file)
        config_dict = ds.deserialize(content)
    return config_dict


def get_local_whois_server_info(suffix=None):
    config_dict = load_whois_server_config()
    whois_server = ''
    if suffix in config_dict:
        whois_server = config_dict[suffix][0]
    return whois_server


def get_data_from_whois_server(server=None, domain=None, timeout=5):
    data = {}
    socket.setdefaulttimeout(timeout)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.connect((server, 43))
    except:
        s.close()
        data['code'] = 500
        data['info'] = 'Can not connect to the server'
        return data

    s_msg = '%s\r\n' % domain
    s_msg = s_msg.encode()
    s.send(s_msg)
    info = ''
    while 1:
        try:
            res = s.recv(1024)
            res = res.decode()
        except:
            s.close()
            data['code'] = 501
            data['info'] = 'Connect to the server timeout'
            return data
        if not res:
            break
        else:
            info += res
    s.close()
    # print info
    data['success'] = 1
    data['code'] = 200
    data['info'] = info
    return data


def get_whois_server_config(w_type=None):
    normal_reg_all = [
        re.compile(r'^\s*Domain\sName:\s*(?P<domain_name>.*)$'),
        re.compile(r'^\s*Registry\sDomain\sID:\s*(?P<registrar_domain_id>.*)$'),
        re.compile(r'^\s*Registrar\sWHOIS\sServer:\s*(?P<registrar_whois_server>.*)$'),
        re.compile(r'^\s*Registrar\sURL:\s*(?P<registrar_url>.*)$'),
        re.compile(r'^\s*Updated\sDate:\s*(?P<updated_date>.*)$'),
        re.compile(r'^\s*Creation\sDate:\s*(?P<creation_date>.*)$'),
        re.compile(r'^\s*Registry\sExpiry\sDate:\s*(?P<registrar_expiry_date>.*)$'),
        re.compile(r'^\s*Registrar:\s*(?P<registrar>.*)$'),
        re.compile(r'^\s*Registrar\sIANA\sID:\s*(?P<registrar_inna_id>.*)$'),
        re.compile(r'^\s*Registrar\sAbuse\sContact\sEmail:\s*(?P<registrar_abuse_contact_email>.*)$'),
        re.compile(r'^\s*Registrar\sAbuse\sContact\sPhone:\s*(?P<registrar_abuse_contact_phone>.*)$'),
        re.compile(r'^\s*Domain\sStatus:\s*(?P<domain_status>.*)$'),
        re.compile(r'^\s*Name\sServer:\s*(?P<name_server>.*)$'),
        re.compile(r'^\s*DNSSEC:\s*(?P<dnssec>.*)$'),
    ]

    cn_reg_all = [
        re.compile(r'^\s*Domain\sName:\s*(?P<domain_name>.*)$'),
        re.compile(r'^\s*ROID:\s*(?P<roid>.*)$'),
        re.compile(r'^\s*Registration\sTime:\s*(?P<registration_time>.*)$'),
        re.compile(r'^\s*Expiration\sTime:\s*(?P<expiration_time>.*)$'),
        re.compile(r'^\s*Registrant:\s*(?P<registrant>.*)$'),
        re.compile(r'^\s*Registrant\sContact Email:\s*(?P<registrant_contact_email>.*)$'),
        re.compile(r'^\s*Name\sServer:\s*(?P<name_server>.*)$'),
        re.compile(r'^\s*DNSSEC:\s*(?P<dnssec>.*)$'),
    ]

    inna_reg_all = [
        re.compile(r'^\s*refer:\s*(?P<refer>.*)$'),
        re.compile(r'^\s*domain:\s*(?P<domain>.*)$'),
        re.compile(r'^\s*organisation:\s*(?P<organisation>.*)$'),
        re.compile(r'^\s*nserver:\s*(?P<nserver>.*)$'),
        re.compile(r'^\s*whois:\s*(?P<whois>.*)$'),
        re.compile(r'^\s*status:\s*(?P<status>.*)$'),
        re.compile(r'^\s*source:\s*(?P<source>.*)$'),
    ]

    cn_whois_config = {'regs': cn_reg_all, }
    normal_whois_config = {'regs': normal_reg_all, }
    inna_whois_config = {'regs': inna_reg_all, }

    configs = {'normal': normal_whois_config, 'cn': cn_whois_config, 'inna': inna_whois_config}
    if w_type in configs:
        return configs[w_type]
    else:
        return normal_whois_config


def get_extra_whois_server_info(domain_name='', get_type='whois_protocol'):
    '''
    获取域名对应的whois server, 全部信息都存储在：inna网站，它支持普通web查询 跟 whois协议查询
    :param domain_name:
    :param get_type: 'whois_protocal'  or 'web'
    :return:
    '''
    whois_text = ''
    if get_type == 'web':
        http_a = Http(is_data_serialize=0)
        http_a.is_debug = False
        http_a.headers = {
            'Referer': 'https://www.iana.org/whois',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        params = {'q': domain_name}
        html_text = http_a.api_connect(http_method='GET', api_url='https://www.iana.org/whois', params=params)
        if html_text is None or html_text == '':
            return {}

        res_tr = r'<pre>(.*?)</pre>'
        m_tr = re.findall(res_tr, html_text, re.S | re.M)  # 截取pre 标签中间的内容
        if len(m_tr) < 1:
            return {}
        whois_text = m_tr[0]
    elif get_type == 'whois_protocol':
        data = get_data_from_whois_server(server='whois.iana.org', domain=domain_name)
        # DD(data)
        if data['code'] != 200:
            print('error !')
            return {}
        whois_text = data['info']

    config = get_whois_server_config(w_type='inna')
    inna_reg_all = config['regs']
    reg_match = None
    linebits = None
    info = {}
    a_lines = split_text_to_list(text=whois_text.lower())
    for l in a_lines:
        for reg in inna_reg_all:
            reg_match = reg.match(l)
            if reg_match is None:
                continue
            linebits = reg_match.groupdict()
            if linebits is None or type(linebits) is not dict:
                continue
            else:
                info = dict(info, **linebits)
                inna_reg_all.remove(reg)  # 删除已经匹配完的正则，加快整个过程执行速度
    return info


def get_extra_whois_server(domain_name=''):
    data = get_extra_whois_server_info(domain_name=domain_name)
    if 'whois' in data:
        return data['whois']
    else:
        return ''


def get_whois_server(domain_name=''):
    data = {}
    data = {'config': get_whois_server_config(w_type='normal'), 'server': None}
    suffix = get_domain_suffix(domain=domain_name)
    suffixs = {
        'com': 'whois.internic.net',
        'net': 'whois.internic.net',
        'cn': 'whois.cnnic.cn',
        'cc': 'whois.nic.cc',
        'org': 'whois.publicinterestregistry.net',
        'com.cn': 'whois.cnnic.cn',
        'net.cn': 'whois.cnnic.cn',
        'info': 'whois.afilias.net',
        'me': 'whois.nic.me',
        'name': 'whois.nic.name',
        'edu': 'whois.educause.edu',
        'edu.cn': 'whois.cnnic.cn',
        'org.cn': 'whois.cnnic.net.cn',
    }
    if suffix in suffixs:
        data['server'] = suffixs[suffix]
    else:
        w1 = get_local_whois_server_info(suffix=suffix)
        if w1 != '':
            data['server'] = w1
        else:
            w2 = get_extra_whois_server(domain_name=domain_name)
            if w2 != '':
                data['server'] = w2
    if data['server'] in ['whois.cnnic.net.cn', 'cwhois.cnnic.cn', 'whois.cnnic.cn']:
        data['config'] = get_whois_server_config(w_type='cn')
    return data


def merge(left, right):
    i, j = 0, 0
    result = []
    while i < len(left) and j < len(right):
        if len(left[i]) <= len(right[j]):
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1
    result += left[i:]
    result += right[j:]
    return result


def merge_sort(lists):
    # 归并排序
    if len(lists) <= 1:
        return lists
    num = int(len(lists) / 2)
    left = merge_sort(lists[:num])
    right = merge_sort(lists[num:])
    return merge(left, right)


def split_domain(domain='', config_file=None):
    '''
    分离域名的顶级域，名称等信息
    :param domain:
    :param config_file:  from https://publicsuffix.org/list/public_suffix_list.dat
    :return:
    '''
    if config_file is None:
        config_file = os.path.join(CONF_DIRS, 'effective_tld_names.dat')
    content = ''
    fh = File()
    content = fh.read_file(rfile=config_file)
    a_lines = []
    for line in content.split('\n'):
        line = line.strip()
        if line.startswith('//') or line == '':
            continue
        a_lines.append(line)
    tld_list = merge_sort(a_lines)  # 归并排序
    tld_list.reverse()  # 反转
    domain = domain.strip().lower()
    domain_s = domain.split('.')
    d_count = len(domain_s)
    for tld in tld_list:
        for i in range(1, d_count):
            suffix = '.'.join(domain_s[i:])
            if sys.version_info < (3, 0, 0):
                suffix = suffix.decode('utf-8')
            if suffix == tld:
                if d_count >= 3:
                    name = '.'.join(domain_s[1:i])
                    site = domain_s[0]
                else:
                    name = '.'.join(domain_s[:i])
                    site = ''
                return (site, name, suffix)
    return ()


def get_domain_suffix(domain=''):
    sv = split_domain(domain=domain)
    if len(sv) >= 3:
        return sv[2]
    else:
        return ''


def format_whois_info(info={}):
    if 'creation_date' in info:
        info['creation_timestamp'] = convert_date_to_timestamp(info['creation_date'])

    if 'registration_time' in info:
        info['creation_timestamp'] = convert_date_to_timestamp(info['registration_time'])

    if 'created_on' in info:
        info['creation_timestamp'] = convert_date_to_timestamp(info['created_on'])

    if 'registry_expiry_date' in info:
        info['expiry_timestamp'] = convert_date_to_timestamp(info['registry_expiry_date'])

    if 'expiration_time' in info:
        info['expiry_timestamp'] = convert_date_to_timestamp(info['expiration_time'])

    if 'expiry_date' in info:
        info['expiry_timestamp'] = convert_date_to_timestamp(info['expiry_date'])

    if 'expiration_date' in info:
        info['expiry_timestamp'] = convert_date_to_timestamp(info['expiration_date'])

    if ('expiry_timestamp' in info and info['expiry_timestamp'] is not None and info[
        'expiry_timestamp'] != '') is False:
        info['expiry_timestamp'] = 0

    if ('creation_timestamp' in info and info['creation_timestamp'] is not None and info[
        'creation_timestamp'] != '') is False:
        info['creation_timestamp'] = 0

    return info


def whois(domain_name=None):
    if domain_name is None or domain_name == '':
        return {}
    w_info = get_whois_server(domain_name=domain_name)
    whois_server = w_info['server']
    if whois_server == '' or whois_server is None:
        return {}
    data = get_data_from_whois_server(server=whois_server, domain=domain_name)
    if data['code'] != 200:
        print('error !')
        return {}
    whois_text = data['info']
    regs = w_info['config']['regs']
    reg_match = None
    linebits = None
    info = {}
    info['name_server'] = []
    name_server_count = 0
    a_lines = split_text_to_list(text=whois_text)
    for l in a_lines:
        for reg in regs:
            reg_match = reg.match(l)
            if reg_match is None:
                continue
            linebits = reg_match.groupdict()
            if linebits is None or type(linebits) is not dict:
                continue
            if 'name_server' in linebits:
                name_server_count = name_server_count + 1
                info['name_server'].append(linebits['name_server'].lower())
                if name_server_count >= 2:
                    regs.remove(reg)  # (一般情况nameserver只有两个)删除已经匹配完的正则，加快整个过程执行速度。
            else:
                info = dict(info, **linebits)
                regs.remove(reg)  # 删除已经匹配完的正则，加快整个过程执行速度。

    return format_whois_info(info=info)


def whois2(domain_name='', is_recursion=True):
    if domain_name is None or domain_name == '':
        return {}
    w_info = get_whois_server(domain_name=domain_name)
    whois_server = w_info['server']
    if whois_server == '' or whois_server is None:
        return {}

    def get_data(whois_server='', domain_name='', info={}, is_recursion=False, recursion_count=1, recursion_max=3):
        r_info = {}
        data = get_data_from_whois_server(server=whois_server, domain=domain_name)
        # print 'recursion_count: %s' % recursion_count
        # print 'whois_server: %s' % whois_server
        if data['code'] != 200:
            print('error !')
            if is_recursion is True and recursion_count == 1:
                # print 'KKKK'
                return {}
            else:
                # print 'LLLL'
                # DD(info)
                return info
        whois_text = data['info']
        a_lines = split_text_to_list(text=whois_text.lower())
        for l in a_lines:
            l = l.strip()
            if l.startswith('for') or l.startswith('url'):
                continue
            kv = l.split(':')
            if len(kv) >= 2:
                r_key = kv[0].replace(' ', '_').replace('/', '_')
                r_val = ':'.join(kv[1:])
                r_val = r_val.strip()
                if r_key in r_info:
                    if type(r_info[r_key]) != list:
                        r_info[r_key] = [r_info[r_key]]
                    r_info[r_key].append(r_val)
                else:
                    r_info[r_key] = r_val
        info = dict(info, **r_info)

        if is_recursion is True and recursion_count <= recursion_max:
            if 'dnssec' in r_info and r_info['dnssec'] == 'unsigned':
                # print 'r_info:'
                # DD(r_info)
                if 'registrar_whois_server' in r_info and whois_server != r_info['registrar_whois_server']:
                    c_info = get_data(whois_server=r_info['registrar_whois_server'], domain_name=domain_name, info=info,
                                      is_recursion=True, recursion_count=recursion_count + 1,
                                      recursion_max=recursion_max)
                    info = dict(info, **c_info)
        return info

    k_info = {}
    for i in range(1, 3):
        k_info = get_data(whois_server=whois_server, domain_name=domain_name, is_recursion=is_recursion,
                          recursion_count=1)
        if len(k_info) > 0:
            break
    return format_whois_info(info=k_info)


class Resolver(Common):
    def __init__(self, *args, **kwargs):
        self.nameservers = kwargs.get('nameservers', [])
        self.use_google_nameserver = kwargs.get('use_google_nameserver', False)
        self.use_tcp = kwargs.get('use_tcp', False)
        self.nameserver_port = kwargs.get('nameserver_port', 53)
        if self.use_google_nameserver:
            self.nameservers = ['8.8.8.8']
        super(Resolver, self).__init__(*args, **kwargs)

    def get_query_ins(self):
        re = None
        if len(self.nameservers) < 1:
            re = resolver.Resolver(configure=True)  # 从系统获取dns设置
            re.port = self.nameserver_port
        else:
            re = resolver.Resolver(configure=False)
            re.nameservers = self.nameservers
            re.port = self.nameserver_port
        return re.query

    def get_domain_ipaddress(self, domain=None):
        IN = rdataclass.IN
        CNAME = rdatatype.CNAME
        # a = resolver.query(domain, 'A')
        query_ins = self.get_query_ins()
        try:
            a = query_ins(qname=domain, rdtype='A', tcp=self.use_tcp)
        except:
            a = None
        new_domain = None
        all_address = []
        if a is None:
            return {'domain': domain, 'all_address': all_address}

        for i in a.response.answer:
            for j in i.items:
                if j.rdtype == CNAME:
                    new_domain = j.to_text()
                if j.rdtype == IN:
                    all_address.append(j.address)
        if new_domain is None:
            return {'domain': domain, 'all_address': all_address}
        else:
            return {'domain': domain, 'new_domian': new_domain, 'all_address': all_address}

    def filte_uri_domain(self, uri=None):
        uri_h = parse_uri(uri=uri)
        return uri_h['hostname']

    def get_url_ipaddress(self, url=None):
        domain_host = {}
        domain = self.filte_uri_domain(uri=url)
        domain_host = self.get_domain_ipaddress(domain=domain)
        return domain_host


if __name__ == '__main__':
    DD(whois(domain_name='spunkmars.com'))
    DD(whois2(domain_name='spunkmars.com'))
    rs_ins = Resolver()
    DD(rs_ins.get_domain_ipaddress('www.spunkmars.com'))