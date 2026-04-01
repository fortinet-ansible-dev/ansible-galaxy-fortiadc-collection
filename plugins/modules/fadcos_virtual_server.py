#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_vdom_enable
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_to_str
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_need_update
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: fadcos_virtual_server
description:
  - Configure virtual server on FortiADC devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

before = {}
after = {}



def set_default_values(module):
    if module.params['iptype'] is None:
        module.params['iptype'] = 'ipv4'
    if module.params['public_iptype'] is None:
        module.params['public_iptype'] = 'ipv4'
    if module.params['port'] is None:
        module.params['port'] = '80'
    if module.params['method'] is None:
        module.params['method'] = 'LB_METHOD_ROUND_ROBIN'
    if module.params['ssl_mirror'] is None:
        module.params['ssl_mirror'] = 'disable'
    if module.params['ssl_mirror_intf'] is None:
        module.params['ssl_mirror_intf'] = ''
    if module.params['traffic_group'] is None:
        module.params['traffic_group'] = 'default'
    if module.params['traffic_log'] is None:
        module.params['traffic_log'] = 'disable'
    if module.params['trans_rate_limit'] is None:
        module.params['trans_rate_limit'] = '0'
    if module.params['warmrate'] is None:
        module.params['warmrate'] = '100'
    if module.params['warmup'] is None:
        module.params['warmup'] = '0'
    if module.params['alone'] is None:
        module.params['alone'] = 'enable'
    if module.params['av_profile'] is None:
        module.params['av_profile'] = ''
    if module.params['client_ssl_profile'] is None:
        module.params['client_ssl_profile'] = ''
    if module.params['clone_pool'] is None:
        module.params['clone_pool'] = ''
    if module.params['clone_traffic_type'] is None:
        module.params['clone_traffic_type'] = ''
    if module.params['connection_limit'] is None:
        module.params['connection_limit'] = '0'
    if module.params['connection_rate_limit'] is None:
        module.params['connection_rate_limit'] = ''
    if module.params['content_rewriting'] is None:
        module.params['content_rewriting'] = 'disable'
    if module.params['content_routing'] is None:
        module.params['content_routing'] = 'disable'
    if module.params['schedule_list'] is None:
        module.params['schedule_list'] = 'disable'
    if module.params['scripting_flag'] is None:
        module.params['scripting_flag'] = 'disable'
    if module.params['waf_profile'] is None:
        module.params['waf_profile'] = ''
    if module.params['dos_profile'] is None:
        module.params['dos_profile'] = ''
    if module.params['captcha_profile'] is None:
        module.params['captcha_profile'] = ''
    if module.params['http2https'] is None:
        module.params['http2https'] = ''
    if module.params['http2https_port'] is None:
        module.params['http2https_port'] = ''
    if module.params['l2_exception_list'] is None:
        module.params['l2_exception_list'] = ''
    if module.params['packet_fwd_method'] is None:
        module.params['packet_fwd_method'] = ''
    if module.params['pagespeed'] is None:
        module.params['pagespeed'] = ''
    if module.params['persistence'] is None:
        module.params['persistence'] = ''
    if module.params['protocol'] is None:
        module.params['protocol'] = '0'
    if module.params['adfs_published_service'] is None:
        module.params['adfs_published_service'] = ''
    if module.params['error_msg'] is None:
        module.params['error_msg'] = 'Server-unavailable!'
    if module.params['error_page'] is None:
        module.params['error_page'] = ''
    if module.params['fortiview'] is None:
        module.params['fortiview'] = 'disable'
    if module.params['wccp'] is None:
        module.params['wccp'] = 'disable'
    if module.params['comments'] is None:
        module.params['comments'] = ''

def add_vs(module, connection):
    set_default_values(module)
    after['added'] = module.params

    name = module.params['name']
    status = module.params['status']
    iptype = module.params['iptype']
    ip = module.params['ip']
    public_iptype = module.params['public_iptype']
    public_ip = module.params['public_ip']
    interface = module.params['interface']
    vstype = module.params['vstype']
    pool = module.params['pool']
    port = module.params['port']
    profile = module.params['profile']
    method = module.params['method']
    ssl_mirror = module.params['ssl_mirror']
    ssl_mirror_intf = module.params['ssl_mirror_intf']
    traffic_group = module.params['traffic_group']
    traffic_log = module.params['traffic_log']
    trans_rate_limit = module.params['trans_rate_limit']
    warmrate = module.params['warmrate']
    warmup = module.params['warmup']
    alone = module.params['alone']
    av_profile = module.params['av_profile']
    client_ssl_profile = module.params['client_ssl_profile']
    clone_pool = module.params['clone_pool']
    clone_traffic_type = module.params['clone_traffic_type']
    connection_limit = module.params['connection_limit']
    connection_rate_limit = module.params['connection_rate_limit']
    content_rewriting = module.params['content_rewriting']
    content_rewriting_list = list_to_str(module.params['content_rewriting_list'])
    content_routing = module.params['content_routing']
    content_routing_list = list_to_str(module.params['content_routing_list'])
    schedule_list = module.params['schedule_list']
    schedule_pool_list = list_to_str(module.params['schedule_pool_list'])
    scripting_flag = module.params['scripting_flag']
    scripting_list = list_to_str(module.params['scripting_list'])
    source_pool_list = list_to_str(module.params['source_pool_list'])
    waf_profile = module.params['waf_profile']
    dos_profile = module.params['dos_profile']
    captcha_profile = module.params['captcha_profile']
    http2https = module.params['http2https']
    http2https_port = module.params['http2https_port']
    l2_exception_list = module.params['l2_exception_list']
    packet_fwd_method = module.params['packet_fwd_method']
    pagespeed = module.params['pagespeed']
    persistence = module.params['persistence']
    protocol = module.params['protocol']
    adfs_published_service = module.params['adfs_published_service']
    error_msg = module.params['error_msg']
    error_page = module.params['error_page']
    fortiview = module.params['fortiview']
    wccp = module.params['wccp']
    comments = module.params['comments']
    vdom = module.params['vdom']

    payload = {'mkey': name,
               'addr-type': iptype,
               'public-ip-type': public_iptype,
               'interface': interface,
               'status': status,
               'pool': pool,
               'port': port,
               'alone': alone,
               'type': vstype,
               'profile': profile,
               'method': method,
               'ssl-mirror': ssl_mirror,
               'ssl-mirror-intf': ssl_mirror_intf,
               'traffic-group': traffic_group,
               'traffic-log': traffic_log,
               'trans-rate-limit': trans_rate_limit,
               'warmrate': warmrate,
               'warmup': warmup,
               'av-profile': av_profile,
               'client_ssl_profile': client_ssl_profile,
               'clone-pool': clone_pool,
               'clone-traffic-type': clone_traffic_type,
               'connection-limit': connection_limit,
               'connection-rate-limit': connection_rate_limit,
               'content-rewriting': content_rewriting,
               'content-rewriting-list': content_rewriting_list,
               'content-routing': content_routing,
               'content-routing-list': content_routing_list,
               'schedule-list': schedule_list,
               'schedule-pool-list': schedule_pool_list,
               'scripting_flag': scripting_flag,
               'scripting_list': scripting_list,
               'source-pool-list': source_pool_list,
               'waf-profile': waf_profile,
               'dos_profile': dos_profile,
               'captcha-profile':captcha_profile,
               'http2https': http2https,
               'http2https-port': http2https_port,
               'l2-exception-list': l2_exception_list,
               'packet-fwd-method': packet_fwd_method,
               'pagespeed': pagespeed,
               'persistence': persistence,
               'protocol': protocol,
               'adfs-published-service': adfs_published_service,
               'error-msg': error_msg,
               'error-page': error_page,
               'comments': comments,
               'fortiview': fortiview,
               'wccp': wccp,
               }

    if iptype == 'ipv6':
        payload['address6'] = ip
    else:
        payload['address'] = ip

    if public_iptype == 'ipv6' and module.params['public_ip']:
        payload['public-ip6'] = public_ip
    elif module.params['public_ip']:
        payload['public-ip'] = public_ip

    url = '/api/load_balance_virtual_server'
    if is_vdom_enable(connection):
        url += '?vdom=' + vdom

    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload)

    return code, response


def edit_vs(module, payload, connection):
    name = module.params['name']
    vdom = module.params['vdom']
    url = '/api/load_balance_virtual_server?mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_vs(module, connection):
    name = module.params['name']
    vdom = module.params['vdom']
    payload = {}
    url = '/api/load_balance_virtual_server'
    if name:
        url += '?mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        if name:
            url += '&vdom=' + vdom
        else:
            url += '?vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_vs(module, connection):
    after['deleted'] = module.params
    name = module.params['name']
    vdom = module.params['vdom']
    payload = {}
    url = '/api/load_balance_virtual_server?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False

# Updated IF statements with before/after tracking
# Variables assumed to exist: module, data, before, after, res

    if module.params['status'] and module.params['status'] != data['status']:
        before['status'] = data['status']
        after['status'] = module.params['status']
        data['status'] = module.params['status']
        res = True
    if module.params['iptype'] and module.params['iptype'] != data['addr-type']:
        before['iptype'] = data['addr-type']
        after['iptype'] = module.params['iptype']
        data['addr-type'] = module.params['iptype']
        res = True
    if data['addr-type'] == 'ipv4' and module.params['ip'] and module.params['ip'] != data['address']:
        before['ip'] = data['address']
        after['ip'] = module.params['ip']
        data['address'] = module.params['ip']
        res = True
    if data['addr-type'] == 'ipv6' and module.params['ip'] and module.params['ip'] != data['address6']:
        before['ip'] = data['address6']
        after['ip'] = module.params['ip']
        data['address6'] = module.params['ip']
        res = True
    if module.params['public_iptype'] and module.params['public_iptype'] != data['public-ip-type']:
        before['public_iptype'] = data['public-ip-type']
        after['public_iptype'] = module.params['public_iptype']
        data['public-ip-type'] = module.params['public_iptype']
        res = True
    if data['public-ip-type'] == 'ipv4' and module.params['public_ip'] and module.params['public_ip'] != data['public-ip']:
        before['public_ip'] = data['public-ip']
        after['public_ip'] = module.params['public_ip']
        data['public-ip'] = module.params['public_ip']
        res = True
    if data['public-ip-type'] == 'ipv6' and module.params['public_ip'] and module.params['public_ip'] != data['public-ip6']:
        before['public_ip'] = data['public-ip6']
        after['public_ip'] = module.params['public_ip']
        data['public-ip6'] = module.params['public_ip']
        res = True
    if module.params['interface'] and module.params['interface'] != data['interface']:
        before['interface'] = data['interface']
        after['interface'] = module.params['interface']
        data['interface'] = module.params['interface']
        res = True
    if module.params['status'] and module.params['status'] != data['status']:
        before['status'] = data['status']
        after['status'] = module.params['status']
        data['status'] = module.params['status']
        res = True
    if module.params['pool'] and module.params['pool'] != data['pool']:
        before['pool'] = data['pool']
        after['pool'] = module.params['pool']
        data['pool'] = module.params['pool']
        res = True
    if module.params['port'] and module.params['port'] != data['port']:
        before['port'] = data['port']
        after['port'] = module.params['port']
        data['port'] = module.params['port']
        res = True
    if module.params['alone'] and module.params['alone'] != data['alone']:
        before['alone'] = data['alone']
        after['alone'] = module.params['alone']
        data['alone'] = module.params['alone']
        res = True
    if module.params['vstype'] and module.params['vstype'] != data['type']:
        before['vstype'] = data['type']
        after['vstype'] = module.params['vstype']
        data['type'] = module.params['vstype']
        res = True
    if module.params['profile'] and module.params['profile'] != data['profile']:
        before['profile'] = data['profile']
        after['profile'] = module.params['profile']
        data['profile'] = module.params['profile']
        res = True
    if module.params['method'] and module.params['method'] != data['method']:
        before['method'] = data['method']
        after['method'] = module.params['method']
        data['method'] = module.params['method']
        res = True
    if module.params['ssl_mirror'] and module.params['ssl_mirror'] != data['ssl-mirror']:
        before['ssl_mirror'] = data['ssl-mirror']
        after['ssl_mirror'] = module.params['ssl_mirror']
        data['ssl-mirror'] = module.params['ssl_mirror']
        res = True
    if module.params['ssl_mirror_intf'] and module.params['ssl_mirror_intf'] != data['ssl-mirror-intf']:
        before['ssl_mirror_intf'] = data['ssl-mirror-intf']
        after['ssl_mirror_intf'] = module.params['ssl_mirror_intf']
        data['ssl-mirror-intf'] = module.params['ssl_mirror_intf']
        res = True
    if module.params['traffic_group'] and module.params['traffic_group'] != data['traffic-group']:
        before['traffic_group'] = data['traffic-group']
        after['traffic_group'] = module.params['traffic_group']
        data['traffic-group'] = module.params['traffic_group']
        res = True
    if module.params['traffic_log'] and module.params['traffic_log'] != data['traffic-log']:
        before['traffic_log'] = data['traffic-log']
        after['traffic_log'] = module.params['traffic_log']
        data['traffic-log'] = module.params['traffic_log']
        res = True
    if module.params['trans_rate_limit'] and module.params['trans_rate_limit'] != data['trans-rate-limit']:
        before['trans_rate_limit'] = data['trans-rate-limit']
        after['trans_rate_limit'] = module.params['trans_rate_limit']
        data['trans-rate-limit'] = module.params['trans_rate_limit']
        res = True
    if module.params['warmrate'] and module.params['warmrate'] != data['warmrate']:
        before['warmrate'] = data['warmrate']
        after['warmrate'] = module.params['warmrate']
        data['warmrate'] = module.params['warmrate']
        res = True
    if module.params['warmup'] and module.params['warmup'] != data['warmup']:
        before['warmup'] = data['warmup']
        after['warmup'] = module.params['warmup']
        data['warmup'] = module.params['warmup']
        res = True
    if module.params['av_profile'] and module.params['av_profile'] != data['av-profile']:
        before['av_profile'] = data['av-profile']
        after['av_profile'] = module.params['av_profile']
        data['av-profile'] = module.params['av_profile']
        res = True
    if module.params['client_ssl_profile'] and module.params['client_ssl_profile'] != data['client_ssl_profile']:
        before['client_ssl_profile'] = data['client_ssl_profile']
        after['client_ssl_profile'] = module.params['client_ssl_profile']
        data['client_ssl_profile'] = module.params['client_ssl_profile']
        res = True
    if module.params['clone_pool'] and module.params['clone_pool'] != data['clone-pool']:
        before['clone_pool'] = data['clone-pool']
        after['clone_pool'] = module.params['clone_pool']
        data['clone-pool'] = module.params['clone_pool']
        res = True
    if module.params['clone_traffic_type'] and module.params['clone_traffic_type'] != data['clone-traffic-type']:
        before['clone_traffic_type'] = data['clone-traffic-type']
        after['clone_traffic_type'] = module.params['clone_traffic_type']
        data['clone-traffic-type'] = module.params['clone_traffic_type']
        res = True
    if module.params['connection_limit'] and module.params['connection_limit'] != data['connection-limit']:
        before['connection_limit'] = data['connection-limit']
        after['connection_limit'] = module.params['connection_limit']
        data['connection-limit'] = module.params['connection_limit']
        res = True
    if module.params['connection_rate_limit'] and module.params['connection_rate_limit'] != data['connection-rate-limit']:
        before['connection_rate_limit'] = data['connection-rate-limit']
        after['connection_rate_limit'] = module.params['connection_rate_limit']
        data['connection-rate-limit'] = module.params['connection_rate_limit']
        res = True
    if module.params['content_rewriting'] and module.params['content_rewriting'] != data['content-rewriting']:
        before['content_rewriting'] = data['content-rewriting']
        after['content_rewriting'] = module.params['content_rewriting']
        data['content-rewriting'] = module.params['content_rewriting']
        res = True
    content_rewriting_list = list_to_str(module.params['content_rewriting_list']).lstrip()
    if content_rewriting_list and content_rewriting_list != data['content-rewriting-list']:
        before['content_rewriting_list'] = data['content-rewriting-list']
        after['content_rewriting_list'] = content_rewriting_list
        data['content-rewriting-list'] = content_rewriting_list
        res = True
    if module.params['content_routing'] and module.params['content_routing'] != data['content-routing']:
        before['content_routing'] = data['content-routing']
        after['content_routing'] = module.params['content_routing']
        data['content-routing'] = module.params['content_routing']
        res = True
    if list_need_update(module.params['content_routing_list'], data['content-routing-list']):
        before['content_routing_list'] = data['content-routing-list']
        after['content_routing_list'] = module.params['content_routing_list']
        data['content-routing-list'] = list_to_str(module.params['content_routing_list'])
        res = True
    if module.params['schedule_list'] and module.params['schedule_list'] != data['schedule-list']:
        before['schedule_list'] = data['schedule-list']
        after['schedule_list'] = module.params['schedule_list']
        data['schedule-list'] = module.params['schedule_list']
        res = True
    if list_need_update(module.params['schedule_pool_list'], data['schedule-pool-list']):
        before['schedule_pool_list'] = data['schedule-pool-list']
        after['schedule_pool_list'] = module.params['schedule_pool_list']
        data['schedule-pool-list'] = list_to_str(module.params['schedule_pool_list'])
        res = True
    if module.params['scripting_flag'] and module.params['scripting_flag'] != data['scripting_flag']:
        before['scripting_flag'] = data['scripting_flag']
        after['scripting_flag'] = module.params['scripting_flag']
        data['scripting_flag'] = module.params['scripting_flag']
        res = True
    if list_need_update(module.params['scripting_list'], data['scripting_list']):
        before['scripting_list'] = data['scripting_list']
        after['scripting_list'] = module.params['scripting_list']
        data['scripting_list'] = list_to_str(module.params['scripting_list'])
        res = True
    if list_need_update(module.params['source_pool_list'], data['source-pool-list']):
        before['source_pool_list'] = data['source-pool-list']
        after['source_pool_list'] = module.params['source_pool_list']
        data['source-pool-list'] = list_to_str(module.params['source_pool_list'])
        res = True
    if module.params['waf_profile'] and module.params['waf_profile'] != data['waf-profile']:
        before['waf_profile'] = data['waf-profile']
        after['waf_profile'] = module.params['waf_profile']
        data['waf-profile'] = module.params['waf_profile']
        res = True
    if module.params['dos_profile'] and  ('dos_profile' not in data or module.params['dos_profile'] != data['dos_profile']):
        if 'dos_profile' not in data:
            data['dos_profile'] = ""
        before['dos_profile'] = data['dos_profile']
        after['dos_profile'] = module.params['dos_profile']
        data['dos_profile'] = module.params['dos_profile']
        res = True
    if module.params['captcha_profile'] and ('captcha-profile' not in data or module.params['captcha_profile'] != data['captcha-profile']):
        if 'captcha-profile' not in data:
            data['captcha-profile'] = ""
        before['captcha_profile'] = data['captcha-profile']
        after['captcha_profile'] = module.params['captcha_profile']
        data['captcha-profile'] = module.params['captcha_profile']
        res = True
    if module.params['http2https'] and module.params['http2https'] != data['http2https']:
        before['http2https'] = data['http2https']
        after['http2https'] = module.params['http2https']
        data['http2https'] = module.params['http2https']
        res = True
    if module.params['http2https_port'] and module.params['http2https_port'] != data['http2https-port']:
        before['http2https_port'] = data['http2https-port']
        after['http2https_port'] = module.params['http2https_port']
        data['http2https-port'] = module.params['http2https_port']
        res = True
    if module.params['l2_exception_list'] and module.params['l2_exception_list'] != data['l2-exception-list']:
        before['l2_exception_list'] = data['l2-exception-list']
        after['l2_exception_list'] = module.params['l2_exception_list']
        data['l2-exception-list'] = module.params['l2_exception_list']
        res = True
    if module.params['packet_fwd_method'] and module.params['packet_fwd_method'] != data['packet-fwd-method']:
        before['packet_fwd_method'] = data['packet-fwd-method']
        after['packet_fwd_method'] = module.params['packet_fwd_method']
        data['packet-fwd-method'] = module.params['packet_fwd_method']
        res = True
    if module.params['pagespeed'] and module.params['pagespeed'] != data['pagespeed']:
        before['pagespeed'] = data['pagespeed']
        after['pagespeed'] = module.params['pagespeed']
        data['pagespeed'] = module.params['pagespeed']
        res = True
    if module.params['persistence'] and module.params['persistence'] != data['persistence']:
        before['persistence'] = data['persistence']
        after['persistence'] = module.params['persistence']
        data['persistence'] = module.params['persistence']
        res = True
    if module.params['protocol'] and module.params['protocol'] != data['protocol']:
        before['protocol'] = data['protocol']
        after['protocol'] = module.params['protocol']
        data['protocol'] = module.params['protocol']
        res = True
    if module.params['adfs_published_service'] and module.params['adfs_published_service'] != data['adfs-published-service']:
        before['adfs_published_service'] = data['adfs-published-service']
        after['adfs_published_service'] = module.params['adfs_published_service']
        data['adfs-published-service'] = module.params['adfs_published_service']
        res = True
    if module.params['error_msg'] and module.params['error_msg'] != data['error-msg']:
        before['error_msg'] = data['error-msg']
        after['error_msg'] = module.params['error_msg']
        data['error-msg'] = module.params['error_msg']
        res = True
    if module.params['error_page'] and module.params['error_page'] != data['error-page']:
        before['error_page'] = data['error-page']
        after['error_page'] = module.params['error_page']
        data['error-page'] = module.params['error_page']
        res = True
    if module.params['comments'] and module.params['comments'] != data['comments']:
        before['comments'] = data['comments']
        after['comments'] = module.params['comments']
        data['comments'] = module.params['comments']
        res = True
    if module.params['fortiview'] and module.params['fortiview'] != data['fortiview']:
        before['fortiview'] = data['fortiview']
        after['fortiview'] = module.params['fortiview']
        data['fortiview'] = module.params['fortiview']
        res = True
    if module.params['wccp'] and module.params['wccp'] != data['wccp']:
        before['wccp'] = data['wccp']
        after['wccp'] = module.params['wccp']
        data['wccp'] = module.params['wccp']
        res = True


    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'edit' or action == 'delete') and not module.params['name']:
        err_msg.append('The name need to set.')
        res = False
    if action == 'add' and not module.params['status']:
        err_msg.append('The status need to set.')
        res = False
    if action == 'add' and not module.params['ip']:
        err_msg.append('The ip or ipv6 must be set.')
        res = False
    if is_vdom_enable(connection) and not module.params['vdom']:
        err_msg.append(
            'The vdom is enable in system setting, vdom must be set.')
        res = False
    elif is_vdom_enable(connection) and module.params['vdom'] and not is_user_in_vdom(connection, module.params['vdom']):
        err_msg.append('The user can not accsee the vdom ' +
                       module.params['vdom'])
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        status=dict(type='str'),
        iptype=dict(type='str'),
        ip=dict(type='str'),
        public_ip=dict(type='str'),
        public_iptype=dict(type='str'),
        interface=dict(type='str'),
        vstype=dict(type='str'),
        pool=dict(type='str'),
        port=dict(type='str'),
        profile=dict(type='str'),
        method=dict(type='str'),
        ssl_mirror=dict(type='str'),
        ssl_mirror_intf=dict(type='str'),
        traffic_group=dict(type='str'),
        traffic_log=dict(type='str'),
        trans_rate_limit=dict(type='str'),
        warmrate=dict(type='str'),
        warmup=dict(type='str'),
        alone=dict(type='str'),
        av_profile=dict(type='str'),
        client_ssl_profile=dict(type='str'),
        clone_pool=dict(type='str'),
        clone_traffic_type=dict(type='str'),
        connection_limit=dict(type='str'),
        connection_rate_limit=dict(type='str'),
        content_rewriting=dict(type='str'),
        content_rewriting_list=dict(type='list'),
        content_routing=dict(type='str'),
        content_routing_list=dict(type='list'),
        schedule_list=dict(type='str'),
        schedule_pool_list=dict(type='list'),
        scripting_flag=dict(type='str'),
        scripting_list=dict(type='list'),
        source_pool_list=dict(type='list'),
        waf_profile=dict(type='str'),
        dos_profile=dict(type='str'),
        captcha_profile=dict(type='str'),
        http2https=dict(type='str'),
        http2https_port=dict(type='str'),
        l2_exception_list=dict(type='str'),
        packet_fwd_method=dict(type='str'),
        pagespeed=dict(type='str'),
        persistence=dict(type='str'),
        protocol=dict(type='str'),
        adfs_published_service=dict(type='str'),
        error_msg=dict(type='str'),
        error_page=dict(type='str'),
        fortiview=dict(type='str'),
        wccp=dict(type='str'),
        comments=dict(type='str'),
        vdom=dict(type='str'),
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True,
                           required_if=required_if)
    connection = Connection(module._socket_path)

    action = module.params['action']
    result = {}
    param_pass, param_err = param_check(module, connection)
    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
        module.exit_json(**result)
    code, data = get_vs(module, connection)
    if action == 'add':
        code, response = add_vs(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_vs(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_vs(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_vs(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_vs(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            code, response = delete_vs(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['failed'] = False
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    if 'res' in result.keys() and type(result['res']) is dict\
            and type(result['res']['payload']) is int and result['res']['payload'] < 0:
        result['err_msg'] = get_err_msg(connection, result['res']['payload'])
        result['changed'] = False
        result['failed'] = True
        if result['res']['payload'] == -13 or result['res']['payload'] == -15:
            result['failed'] = False

    if 'changed' in result.keys() and result['changed'] == True:
        result['diff'] = {
            'before': before,
            'after': after
        }

    module.exit_json(**result)


if __name__ == '__main__':
    main()
