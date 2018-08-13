#!/usr/bin/env python
import sys
import os
import re
import copy
import itertools
import socket
import struct
import netifaces
from netaddr import IPAddress, IPNetwork
import jinja2

node_width = 10
caption_len = 25

(hostname, _, local_dns) = socket.gethostname().partition('.')

local_gateway = None
local_ip = None
local_subnet = None
with open('/proc/net/route') as fh:
    for line in fh:
        fields = line.strip().split()
        if fields[1] != '00000000' or not int(fields[3], 16) & 2:
            continue
        local_gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
        interface = fields[0]
        try:
            address = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
            local_ip = IPNetwork('%s/%s' % (address['addr'], address['netmask']))
            local_subnet = IPNetwork('%s/%s' % (local_ip.network, local_ip.prefixlen))
        except Exception:
            pass
        break

multi_intf = False
data_subnet = None
bms_mgmt_subnet = [None, str(local_subnet)][bool(local_subnet)]
kvm_mgmt_subnet = '192.168.122.0/24'
data_bridge = None
mgmt_bridge = 'default'
data_vip = None
mgmt_vip = None
data_gw = None
bms_mgmt_gw = local_gateway
kvm_mgmt_gw = '192.168.122.1'
kvm_host_address = [None, str(local_ip.ip)][bool(local_ip)]
install = 'BMS'
ntp_server = None
dns_suffix = local_dns
dns_server = None
message = None

def get_mgmt_subnet():
    return [bms_mgmt_subnet, kvm_mgmt_subnet][install=='KVM']
def get_mgmt_gw():
    return [bms_mgmt_gw, kvm_mgmt_gw][install=='KVM']
def get_data(cap):
    return ['/', ''][multi_intf] + getattr(['data', ''][multi_intf], ['lower', 'capitalize', 'upper'][cap])()
def get_last_octet(ip):
    return str(ip).rpartition('.')[-1]
def join_host_ip(subnet, ip):
    return '%s.%s' % (str(subnet).rpartition('.')[0], ip)

bms_node = [hostname]
bms_node_info = { hostname: dict(role='all') }
if local_ip is not None and local_subnet is not None:
    bms_node_info[hostname]['mgmt_ip'] = get_last_octet(local_ip.ip)

kvm_node = []
kvm_node_info = {}

def print_topology():

    def trunc_node_name(node):
        tn = node
        if len(tn) > node_width*3:
            tn = tn + '..'
            tn = tn[:node_width*3-2] + tn[-2:]
        tn = re.findall('.{1,%d}' % node_width, tn)
        if len(tn) == 0:
            tn.append('')
        if len(tn) < 3:
            tn.insert(0, '')
        if len(tn) < 3:
            tn.append('')
        tn.append('(%s)' % str(node_info.get(node, {}).get('role')).capitalize())
        return tn

    def trunc_bridge(br):
        if isinstance(br, str) and len(br) > 17:
            br = br + '..'
            br = br[:15] + br[-2:]
        return br

    def lprint(msg):
        if install == 'KVM':
            msg = '|   ' + '%-*s' % (total_width, msg) + '   |'
        elif install == 'BMS':
            msg = '   ' + msg
        cprint(msg)

    def cprint(msg):
        print(re.sub(r'(\[.*\])', r'\033[91m\1\033[0m', msg))

    def multi_control():
        return bool(sum([ node_info[n].get('role') in ['all', 'control'] for n in node ]) >= 2)

    if install == 'KVM':
        node = kvm_node
        node_info = kvm_node_info
    else:
        node = bms_node
        node_info = bms_node_info

    os.system('clear')
    total_node_width = (node_width+3) * len(node) + [0,4][len(node)==1]
    total_width = caption_len + total_node_width
    str_data_subnet = '%-*s' % (caption_len, '%s' % (data_subnet or '[data subnet]'))
    str_mgmt_subnet = '%-*s' % (caption_len, '%s' % (get_mgmt_subnet() or '[mgmt' + get_data(0) + ' subnet]'))
    str_data_bridge = '%-*s' % (caption_len, 'Bridge: %s' % (trunc_bridge(data_bridge) or '[data bridge]'))
    str_mgmt_bridge = '%-*s' % (caption_len, 'Bridge: %s' % (trunc_bridge(mgmt_bridge) or '[mgmt bridge]'))
    str_vertical_line = ' '*int(bool(node)) + (' '*3).join(['|'.center(node_width)] * len(node))

    node_data_border = '+' + ['', 'eth1'][install=='KVM' and multi_intf].center(node_width, '-') + '+ '
    node_mgmt_border = '+' + ['', 'eth0'][install=='KVM'].center(node_width, '-') + '+ '

    print('\033[94m*** ' + install + ' installation ***\033[0m')
    if install == 'KVM':
        print('\033[93mIt helps to provision the KVM instance. If you created the server already, choose BMS instead.\033[0m')
    print('')

    if install == 'KVM':
        title = ' KVM HOST - %s ' % (kvm_host_address or '[ip_address]')
        cprint('+' + title.center(total_width+6, '-') + '+')
        print('\n'.join(['|' + ' '*(total_width+6) + '|']*1))

    if multi_intf:
        if len(node) > 0:
            lprint(' '*caption_len + ('+' + '-'*15 + '+').center(total_node_width))
            lprint(' '*caption_len + '|vRouter Gateway|'.center(total_node_width))
            lprint(' '*caption_len + ('|' + (data_gw or '[vrouter_gw]').center(15) + '|').center(total_node_width))
            lprint(' '*caption_len + ('+' + '-'*15 + '+').center(total_node_width))
        lprint([' '*caption_len, str_data_bridge][install=='KVM'] + ['', '|'.center(total_node_width)][len(node)>0])
        lprint('DATA NETWORK '.ljust(caption_len, '-')
               + (['', 'VIP: %s' % (data_vip or '[data vip]')][multi_control()]).center(total_node_width, '-'))
        lprint(str_data_subnet + str_vertical_line)
        lprint(' '*caption_len + ' '*int(bool(node))
               +(' '*3).join([ (['','.'][bool(node_info.get(n, {}).get('data_ip'))]
                                + str(node_info.get(n, {}).get('data_ip') or '[data_ip]')).center(node_width) for n in node ]))
        lprint(' '*caption_len + str_vertical_line)

    lprint(' '*caption_len + node_data_border * len(node))
    trunc_node = map(trunc_node_name, node)
    for i in range(4):
        lprint(' '*caption_len + '|'*int(bool(node)) + '| |'.join([n[i].center(node_width) for n in trunc_node]) + '|'*int(bool(node)))
    lprint(' '*caption_len + node_mgmt_border * len(node))

    lprint(' '*caption_len + str_vertical_line)
    lprint(' '*caption_len + ' '*int(bool(node))
           +(' '*3).join([ (['','.'][bool(node_info.get(n, {}).get('mgmt_ip'))]
                            + str(node_info.get(n, {}).get('mgmt_ip') or '[mgmt_ip]')).center(node_width) for n in node ]))
    lprint([' '*caption_len, str_mgmt_bridge][install=='KVM'] + str_vertical_line)

    lprint(('MGMT' + get_data(2) + ' NETWORK ').ljust(caption_len, '-')
           + (['','VIP: %s' % (mgmt_vip or '[mgmt vip]')][multi_control()]).center(total_node_width, '-'))
    lprint(str_mgmt_subnet + ['', '|'.center(total_node_width)][len(node)>0])
    if len(node) > 0:
        lprint(' '*caption_len + ('+' + '-'*15 + '+').center(total_node_width))
        lprint(' '*caption_len + '|  Mgmt Gateway |'.center(total_node_width))
        lprint(' '*caption_len + ('|' + (get_mgmt_gw() or '[mgmt_gw]').center(15) + '|').center(total_node_width))
        lprint(' '*caption_len + ('+' + '-'*15 + '+').center(total_node_width))

    if install == 'KVM':
        print('\n'.join(['|' + ' '*(total_width+6) + '|']*1))
        print('+' + '-'*(total_width+6) + '+')

    print('')
    cprint('NTP Server: %s' % (ntp_server or '[ntp_server]'))
    if install == 'KVM':
        cprint('DNS Server: %s' % (dns_server or '[dns_server]'))
    cprint('DNS Suffix: %s' % (dns_suffix or '[dns_suffix]'))
    print('')

    if message:
        msg = message
        if isinstance(msg, list):
            msg = '\n'.join(msg)
        print('\033[91m%s\033[0m\n' % msg)

ans = True
try:
    while True:
        print_topology()

        if install == 'KVM':
            node = kvm_node
            node_info = kvm_node_info
        else:
            node = bms_node
            node_info = bms_node_info

        choices = [
            'Toggle between KVM/BMS installation',
            'Toggle between Single/Multi interface',
            'Add/Update %s node' % install,
            'Remove %s node' % install]

        if multi_intf:
            choices.append('Configure Data subnet')
        choices.append('Configure Mgmt%s subnet' % get_data(1))

        if len(node) > 0:
            if multi_intf:
                choices.append('Configure Data(vRouter) gateway')
            choices.append('Configure Mgmt%s gateway' % get_data(1))

        if install == 'KVM':
            if multi_intf:
                choices.append('Configure Data bridge')
            choices.extend(['Configure Mgmt%s bridge' % get_data(1),
                            'Configure KVM host IP address'])

        if sum([ node_info[n].get('role') in ['all', 'control'] for n in node ]) >= 2:
            if multi_intf:
                choices.append('Configure Data VIP address')
            choices.append('Configure Mgmt%s VIP address' % get_data(1))

        choices.append('Configure NTP server')
        if install == 'KVM':
            choices.append('Configure DNS server')
        choices.extend(['Configure DNS suffix',
                        'Confirm and generate instances.yaml'])

        choices_enum = list(enumerate(choices, 1))
        choices_chunk = [ choices_enum[i:i+9] for i in range(0, len(choices_enum), 9) ]
        for choice in itertools.izip_longest(*choices_chunk):
            print('   '.join(['%-2s: %-40s' % c for c in choice if c is not None]))

        ans = raw_input('\nYour choice: ')
        message = None

        try:
            if not (re.match('^[0-9]+$', ans) and int(ans) in range(1, len(choices)+1)):
                raise Exception
            ans = choices[int(ans)-1]
        except Exception:
            if ans != '':
                message = 'Invalid choice: %s' % ans
            print_topology()
            continue

        def validate_input(ans, type=None, subnet=None, default=None):
            resp = raw_input(ans.replace('Configure ', '') + '%s: ' % (default and ' [%s]' % default or '')) or (default or '')
            if len(resp) > 0:
                try:
                    if type in ('ip', 'ip_octet'):
                        if subnet:
                            subnet = IPNetwork(subnet)
                        if subnet and re.match('^[0-9]+$', resp) and int(resp) in range(0, 256):
                            resp = join_host_ip(subnet.network, resp)
                        ip = IPAddress(resp)
                        if subnet:
                            if ip not in subnet or ip in (subnet.network, subnet.broadcast):
                                return None, 'IP %s not in the valid range of subnet %s' % (ip, subnet)
                            elif type == 'ip':
                                return str(ip), None
                            else:
                                return get_last_octet(ip), None
                        else:
                            return str(ip), None
                    elif type == 'subnet':
                        network = IPNetwork(resp)
                        return '%s/%s' % (network.network, network.prefixlen), None
                    else:
                        return resp, None
                except Exception:
                    return None, 'Invalid %s: %s' % (ans.replace('Configure ',''), resp)
            elif type == 'not_null':
                return None, 'Please input %s' % ans.replace('Configure ','')
            else:
                return None, None

        if ans == 'Toggle between KVM/BMS installation':
            install = ['BMS', 'KVM'][install=='BMS']

        elif ans == 'Toggle between Single/Multi interface':
            multi_intf = not multi_intf

        elif re.match('^Add/Update (KVM|BMS) node$', ans):
            if not get_mgmt_subnet():
                message = 'Please configure Mgmt%s subnet first' % get_data(1)
                continue
            elif not (data_subnet or not multi_intf):
                message = 'Please configure Data subnet first'
                continue

            node_name, message = validate_input('Node host name', 'not_null')
            if message:
                continue

            default_mgmt_ip = node_info.get(node_name, {}).get('mgmt_ip')
            if default_mgmt_ip:
                default_mgmt_ip = join_host_ip(get_mgmt_subnet(), default_mgmt_ip)
            mgmt_ip, message = validate_input('Mgmt%s IP address (Full IP or last octet)' % get_data(1), 
                                              'ip_octet', get_mgmt_subnet(), default=default_mgmt_ip)
            if message:
                continue

            data_ip = None
            if multi_intf:
                default_data_ip = node_info.get(node_name, {}).get('data_ip')
                if default_data_ip:
                    default_data_ip = join_host_ip(data_subnet, default_data_ip)
                data_ip, message = validate_input('Data IP address (Full IP or last octet)', 'ip_octet', data_subnet, default=default_data_ip)
                if message:
                    continue

            role, message = validate_input('Role (All/Control/Compute)', 'not_null', default=node_info.get(node_name, {}).get('role'))
            if message:
                continue
            role = role.lower()
            if role not in ('all', 'control', 'compute'):
                message = 'Invalid Role (All/Control/Compute): %s' % role
                continue

            if node_name not in node:
                node.append(node_name)
            node_info[node_name] = dict(mgmt_ip=mgmt_ip, data_ip=data_ip, role=role)

        elif re.match('^Remove (KVM|BMS) node$', ans):
            node_name, message = validate_input('Node host name', 'not_null')
            if message:
                continue
            if node_name not in node:
                message = "Node '%s' is not configured" % node_name
                continue
            node.remove(node_name)
            del(node_info[node_name])

        elif re.match('^Configure Mgmt(/Data)? subnet$', ans):
            if install == 'KVM':
                kvm_mgmt_subnet, message = validate_input(ans, 'subnet')
            else:
                bms_mgmt_subnet, message = validate_input(ans, 'subnet')

        elif ans == 'Configure Data subnet':
            data_subnet, message = validate_input(ans, 'subnet')

        elif re.match('^Configure Mgmt(/Data)? gateway$', ans):
            if install == 'KVM':
                kvm_mgmt_gw, message = validate_input(ans + ' (Full IP or last octet)', 'ip', kvm_mgmt_subnet)
            else:
                bms_mgmt_gw, message = validate_input(ans + ' (Full IP or last octet)', 'ip', bms_mgmt_subnet)

        elif ans == 'Configure Data(vRouter) gateway':
            data_gw, message = validate_input(ans + ' (Full IP or last octet)', 'ip', data_subnet)

        elif re.match('^Configure Mgmt(/Data)? bridge$', ans):
            mgmt_bridge, message = validate_input(ans)

        elif ans == 'Configure Data bridge':
            data_bridge, message = validate_input(ans)

        elif ans == 'Configure KVM host IP address':
            kvm_host_address, message = validate_input(ans, 'ip')

        elif re.match('^Configure Mgmt(/Data)? VIP address$', ans):
            mgmt_vip, message = validate_input(ans + ' (Full IP or last octet)', 'ip', get_mgmt_subnet())

        elif ans == 'Configure Data VIP address':
            data_vip, message = validate_input(ans + ' (Full IP or last octet)', 'ip', data_subnet)

        elif ans == 'Configure NTP server':
            ntp_server, message = validate_input(ans, 'ip')

        elif ans == 'Configure DNS server':
            dns_server, message = validate_input(ans, 'ip')

        elif ans == 'Configure DNS suffix':
            dns_suffix, message = validate_input(ans)

        elif ans == 'Confirm and generate instances.yaml':
            message = []
            if install == 'KVM':
                if not kvm_host_address:
                    message.append('Please configure KVM host IP address')
                if not mgmt_bridge:
                    message.append('Please configure Mgmt%s bridge' % get_data(1))
                if multi_intf:
                    if not data_bridge:
                        message.append('Please configure Data bridge')
                    elif mgmt_bridge == data_bridge:
                        message.append('Please configure different Mgmt and Data bridge')

            if not get_mgmt_subnet():
                message.append('Please configure Mgmt%s subnet' % get_data(1))
            if multi_intf:
                if not data_subnet:
                    message.append('Please configure Data subnet')
                elif get_mgmt_subnet():
                    if IPNetwork(data_subnet) == IPNetwork(get_mgmt_subnet()):
                        message.append('Please configure different Mgmt and Data subnet')
                    elif IPNetwork(data_subnet) in IPNetwork(get_mgmt_subnet()) or IPNetwork(get_mgmt_subnet()) in IPNetwork(data_subnet):
                        message.append('Please configure non-overlap Mgmt and Data subnet')

            if len(node) == 0:
                message.append('Please add a %s node' % install)
            else:
                if len(node) == 1:
                    if node_info[node[0]].get('role') != 'all':
                        message.append("Please configure 'all' role for single node scenario")
                else:
                    if sum([ node_info[n].get('role') in ['all', 'control'] for n in node ]) == 0:
                        message.append("Please at least configure one 'control' node")
                    if sum([ node_info[n].get('role') in ['all', 'compute'] for n in node ]) == 0:
                        message.append("Please at least configure one 'compute' node")
                    if sum([ node_info[n].get('role') == 'all' for n in node ]) > 0:
                        message.append("Please configure 'control' or 'compute' role for multi-node scenario")

                if get_mgmt_subnet() and (not multi_intf or data_subnet):
                    mgmt_ip_list = []
                    data_ip_list = []
                    for n in node:
                        if not node_info[n].get('mgmt_ip'):
                            message.append("Please configure Mgmt%s IP for node '%s'" % (get_data(1), n))
                        else:
                            ip = IPAddress(join_host_ip(get_mgmt_subnet(), node_info[n].get('mgmt_ip')))
                            subnet = IPNetwork(get_mgmt_subnet())
                            if ip in mgmt_ip_list:
                                message.append("Node '%s' has duplicate Mgmt%s IP %s" % (n, get_data(1), ip))
                            elif ip not in subnet or ip in (subnet.network, subnet.broadcast):
                                message.append("Node '{0}' Mgmt{1} IP address {2} not in the valid range of Mgmt{1} subnet {3}".format(
                                    n, get_data(1), ip, subnet))
                            else:
                                mgmt_ip_list.append(ip)

                        if multi_intf and not node_info[n].get('data_ip'):
                            message.append("Please configure Data IP for node '%s'" % n)
                        elif multi_intf:
                            ip = IPAddress(join_host_ip(data_subnet, node_info[n].get('data_ip')))
                            subnet = IPNetwork(data_subnet)
                            if ip in data_ip_list:
                                message.append("Node '%s' has duplicate Data IP %s" % (n, ip))
                            elif ip not in subnet or ip in (subnet.network, subnet.broadcast):
                                message.append("Node '%s' Data IP address %s not in the valid range of Data subnet %s" % (
                                    n, ip, subnet))
                            else:
                                data_ip_list.append(ip)

                    if sum([ node_info[n].get('role') in ['all', 'control'] for n in node ]) >= 2:
                        if not mgmt_vip:
                            message.append('Please configure Mgmt%s VIP address' % get_data(1))
                        else:
                            ip = IPAddress(mgmt_vip)
                            subnet = IPNetwork(get_mgmt_subnet())
                            if ip not in subnet or ip in (subnet.network, subnet.broadcast):
                                message.append('Mgmt{0} VIP address {1} not in the valid range of Mgmt{0} subnet {2}'.format(
                                    get_data(1), ip, subnet))
                            elif ip in mgmt_ip_list:
                                message.append('Mgmt%s VIP address %s is duplicate with node IP' % (get_data(1), ip))
                            else:
                                mgmt_ip_list.append(ip)

                        if multi_intf:
                            if not data_vip:
                                message.append('Please configure Data VIP address')
                            else:
                                ip = IPAddress(data_vip)
                                subnet = IPNetwork(subnet)
                                if ip not in subnet or ip in (subnet.network, subnet.broadcast):
                                    message.append('Data VIP address %s not in the valid range of Data subnet %s' % (ip, subnet))
                                elif ip in data_ip_list:
                                    message.append('Data VIP address %s is duplicate with node IP' % ip)
                                else:
                                    data_ip_list.append(ip)

                    if not get_mgmt_gw():
                        message.append('Please configure Mgmt%s gateway' % get_data(1))
                    else:
                        ip = IPAddress(get_mgmt_gw())
                        subnet = IPNetwork(get_mgmt_subnet())
                        if ip not in subnet or ip in (subnet.network, subnet.broadcast):
                            message.append('Mgmt{0} gateway {1} not in the valid range of Mgmt{0} subnet {2}'.format(
                                get_data(1), ip, subnet))
                        elif ip in mgmt_ip_list:
                            message.append('Mgmt%s gateway %s is duplicate with node IP' % (get_data(1), ip))
                        else:
                            mgmt_ip_list.append(ip)

                    if multi_intf:
                        if not data_gw:
                            message.append('Please configure Data(vRouter) gateway')
                        else:
                            ip = IPAddress(data_gw)
                            subnet = IPNetwork(data_subnet)
                            if ip not in subnet or ip in (subnet.network, subnet.broadcast):
                                message.append('Data(vRouter) gateway %s not in the valid range of Data subnet %s' % (data_gw, subnet))
                            elif ip in data_ip_list:
                                message.append('Data gateway %s is duplicate with node IP' % ip)
                            else:
                                data_ip_list.append(ip)

            if not ntp_server:
                message.append('Please configure NTP server')
            if install == 'KVM' and not dns_server:
                message.append('Please configure DNS server')
            if not dns_suffix:
                message.append('Please configure DNS suffix')
            if not message:
                node_infos = copy.deepcopy(node_info)
                bridge = set()
                for n in node:
                    if node_infos[n].get('mgmt_ip'):
                        node_infos[n]['mgmt_ip'] = join_host_ip(get_mgmt_subnet(), node_infos[n]['mgmt_ip'])
                    if node_infos[n].get('data_ip'):
                        node_infos[n]['data_ip'] = join_host_ip(data_subnet, node_infos[n]['data_ip'])
                mgmt_network = IPNetwork(get_mgmt_subnet()).network
                mgmt_netmask = IPNetwork(get_mgmt_subnet()).netmask
                if multi_intf:
                    data_network = IPNetwork(data_subnet).network
                    data_netmask = IPNetwork(data_subnet).netmask
                mgmt_gw = get_mgmt_gw()
                vrouter_gw = [get_mgmt_gw(), data_gw][multi_intf]

                if sum([ node_info[n].get('role') in ['all', 'control'] for n in node ]) < 2:
                    data_vip = None
                    mgmt_vip = None

                try:
                    if int(os.popen('./config/lspci | grep -c -i vmware').read().strip()) > 0:
                        vmware = True
                    if int(os.popen('egrep -c \'(vmx|svm)\' /proc/cpuinfo').read().strip()) == 0:
                        qemu = True
                except Exception:
                    pass

                env = jinja2.Environment(trim_blocks=True, lstrip_blocks=True).from_string(open('config/instances.yaml.j2').read())
                prefix_path = os.path.expanduser('~') + '/contrail-ansible-deployer/config/'
                open(prefix_path + 'instances.yaml', 'w').write(env.render(**globals()))
                open(prefix_path + 'all_hosts', 'w').write('\n'.join([ str(node_infos[n]['mgmt_ip']) for n in node ]) + '\n')
                open(prefix_path + 'install_mode', 'w').write(install + '\n')
                if install == 'KVM':
                    with open(prefix_path + 'kvm_bridge', 'w') as f:
                        f.write(mgmt_bridge + '\n')
                        if multi_intf:
                            f.write(data_bridge + '\n')

                print('Generated config file at %sinstances.yaml' % prefix_path)
                break
except KeyboardInterrupt:
    print('')
    sys.exit()
