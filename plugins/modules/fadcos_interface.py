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
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_global_admin
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fadcos_interfadce
short_description: Manage FortiADC network interface by RESTful API
description:
  - Manage FortiADC network interface by RESTful API
version_added: "2.8"
author: ""
options:
"""

EXAMPLES = """
"""

RETURN = """
"""


def add_interface(module, connection):
    name = module.params['name']
    mode = module.params['mode']
    status = module.params['status']
    IPandMask = module.params['IPandMask']
    IPv6andMask = module.params['IPv6andMask']
    allowaccess = list_to_str(module.params['allowaccess'])
    intf_type = module.params['intf_type']
    vlanid = module.params['vlanid']
    vdom = module.params['vdom']
    interface = module.params['interface']
    mtu = module.params['mtu']
    aggregate_algorithm = module.params['aggregate_algorithm']
    aggregate_mode = module.params['aggregate_mode']
    default_gw = module.params['default_gw']
    dhcp_gw_override = module.params['dhcp_gw_override']
    dhcp_gw_distance = module.params['dhcp_gw_distance']
    disc_retry_timeout = module.params['disc_retry_timeout']
    pppoe_username = module.params['pppoe_username']
    pppoe_passwd = module.params['pppoe_passwd']
    floating = module.params['floating']
    floating_ip = module.params['floating_ip']
    redundant_member = list_to_str(module.params['redundant_member'])
    traffic_group = module.params['traffic_group']

    payload = {'mkey': name,
               'mode': mode,
               'mtu': mtu,
               'ip': IPandMask,
               'ip6': IPv6andMask,
               'interface': interface,
               'allowaccess': allowaccess,
               'type': intf_type,
               'vdom': vdom,
               'vlanid': vlanid,
               'status': status,
               'aggregate-algorithm': aggregate_algorithm,
               'aggregate-mode': aggregate_mode,
               'dedicate-to-management': 'disable',
               'default-gw': default_gw,
               'dhcp_gw_distance': dhcp_gw_distance,
               'dhcp_gw_override': dhcp_gw_override,
               'dhcp_ip_overlap': '1',
               'disc-retry-timeout': disc_retry_timeout,
               'dns-server-override': 'enable',
               'floating': floating,
               'floating-ip': floating_ip,
               'redundant-member': redundant_member,
               'secondary-ip': 'disable',
               'traffic-group': traffic_group,
               'username': pppoe_username,
               }

    url = '/api/system_interface'
    if is_vdom_enable(connection) and not is_global_admin(connection):
        url += '?vdom=' + vdom

    code, response = connection.send_request(url, payload)

    return code, response


def edit_interface(module, payload, connection):
    name = module.params['name']
    url = '/api/system_interface?mkey=' + name
    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_interface(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/system_interface'
    if name:
        url += '?mkey=' + name

    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_interface(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/system_interface?mkey=' + name

    if is_vdom_enable(connection) and not is_global_admin(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False

    if module.params['mode'] and module.params['mode'] != data['mode']:
        data['mode'] = module.params['mode']
        res = True
    if module.params['status'] and module.params['status'] != data['status']:
        data['status'] = module.params['status']
        res = True
    if module.params['IPandMask'] and module.params['IPandMask'] != data['ip']:
        data['ip'] = module.params['IPandMask']
        res = True
    if module.params['IPv6andMask'] and module.params['IPv6andMask'] != data['ipv6']:
        data['ipv6'] = module.params['IPv6andMask']
        res = True
    if module.params['mtu'] and module.params['mtu'] != data['mtu']:
        data['mtu'] = module.params['mtu']
        res = True
    if module.params['intf_type'] and module.params['intf_type'] != data['type']:
        data['type'] = module.params['intf_type']
        res = True
    if list_need_update(module.params['allowaccess'], data['allowaccess']):
        data['allowaccess'] = list_to_str(module.params['allowaccess'])
        res = True
    if list_need_update(module.params['redundant_member'], data['redundant-member']):
        data['redundant-member'] = list_to_str(
            module.params['redundant_member'])
        res = True

    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'edit' or action == 'delete') and not module.params['name']:
        err_msg.append('The name need to set.')
        res = False
    if action == 'add' and module.params['intf_type'] == 'physical':
        err_msg.append('can not create intface type physical.')
        res = False
    if action == 'add' and module.params['intf_type'] == 'vlan' and not module.params['vlanid']:
        err_msg.append('The vlan id must be set when interface type is vlan.')
        res = False
    if action == 'add' and module.params['intf_type'] == 'vlan' and not module.params['interface']:
        err_msg.append(
            'The interface id must be set when interface type is vlan.')
        res = False
    # if action == 'edit' and module.params['intf_type'] == 'vlan' and module.params['vlanid']:
    #    err_msg.append('Can not change vlan id.')
    #    res = False
    # if action == 'edit' and module.params['intf_type'] == 'vlan' and module.params['interface']:
    #    err_msg.append('Can not change interface.')
    #    res = False
    if action == 'add' and not module.params['IPandMask'] and not module.params['IPv6andMask']:
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
        status=dict(type='str', default='up'),
        mode=dict(type='str'),
        IPandMask=dict(type='str'),
        IPv6andMask=dict(type='str'),
        allowaccess=dict(type='list'),
        mtu=dict(type='str', default='1500'),
        intf_type=dict(type='str'),
        vlanid=dict(type='str'),
        vdom=dict(type='str'),
        interface=dict(type='str'),
        aggregate_algorithm=dict(type='str'),
        aggregate_mode=dict(type='str'),
        default_gw=dict(type='str', default='enable'),
        dhcp_gw_override=dict(type='str', default='disable'),
        dhcp_gw_distance=dict(type='str', default='10'),
        disc_retry_timeout=dict(type='str'),
        pppoe_username=dict(type='str'),
        pppoe_passwd=dict(type='str'),
        floating=dict(type='str', default='disable'),
        floating_ip=dict(type='str'),
        redundant_member=dict(type='list'),
        traffic_group=dict(type='str', default='default'),
    )

    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    connection = Connection(module._socket_path)

    action = module.params['action']
    result = {}
    param_pass, param_err = param_check(module, connection)
    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
    elif action == 'add':
        code, response = add_interface(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_interface(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_interface(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            code, response = edit_interface(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_interface(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = delete_interface(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    if 'res' in result.keys() and type(result['res']) is dict\
            and type(result['res']['payload']) is int and result['res']['payload'] < 0:
        result['err_msg'] = get_err_msg(connection, result['res']['payload'])
        result['changed'] = False
        result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
