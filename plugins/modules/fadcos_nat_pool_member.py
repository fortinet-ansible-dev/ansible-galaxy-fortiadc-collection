#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec, is_vdom_enable, get_err_msg, is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: fadcos_nat_pool_member
description:
  - Configure NAT pool member on FortiADC devices via RESTful APIs
"""


def add_nat_pool(module, connection):
    pkey = module.params['natpool_name']
    name = module.params['name']
    interface = module.params['interface']
    pooltype = module.params['pooltype']
    ipmin = module.params['ipmin']
    ipmax = module.params['ipmax']
    vdom = module.params['vdom']

    payload = {'mkey': name,
               'interface': interface,
               'pool_type': pooltype,
               }

    if pooltype == 'ipv6':
        payload['ip6_max'] = ipmax
        payload['ip6_min'] = ipmin
    else:
        payload['ip_max'] = ipmax
        payload['ip_min'] = ipmin

    url = '/api/load_balance_ippool_child_node_member?pkey=' + pkey
    if is_vdom_enable(connection):
        url += '?vdom=' + vdom

    code, response = connection.send_request(url, payload)

    return code, response


def edit_nat_pool(module, payload, connection):
    pkey = module.params['natpool_name']
    name = module.params['name']
    vdom = module.params['vdom']
    url = '/api/load_balance_ippool_child_node_member?pkey=' + pkey + '&mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_nat_pool(module, connection):
    pkey = module.params['natpool_name']
    name = module.params['name']
    vdom = module.params['vdom']
    payload = {}
    url = '/api/load_balance_ippool_child_node_member?pkey=' + pkey
    if name:
        url += '&mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_nat_pool(module, connection):
    pkey = module.params['natpool_name']
    name = module.params['name']
    vdom = module.params['vdom']
    payload = {}
    url = '/api/load_balance_ippool_child_node_member?pkey=' + pkey + '&mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False

    if module.params['interface'] and module.params['interface'] != data['interface']:
        data['interface'] = module.params['interface']
        res = True
    if module.params['pooltype'] and module.params['pooltype'] != data['pool_type']:
        data['pool_type'] = module.params['pooltype']
        res = True
    if data['pool_type'] == 'ipv6':
        if module.params['ipmin'] and module.params['ipmin'] != data['ip6_min']:
            data['ip6_min'] = module.params['ipmin']
            res = True
        if module.params['ipmax'] and module.params['ipmax'] != data['ip6_max']:
            data['ip6_max'] = module.params['ipmax']
            res = True
    else:
        if module.params['ipmin'] and module.params['ipmin'] != data['ip_min']:
            data['ip_min'] = module.params['ipmin']
            res = True
        if module.params['ipmax'] and module.params['ipmax'] != data['ip_max']:
            data['ip_max'] = module.params['ipmax']
            res = True

    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'edit' or action == 'delete') and not module.params['name']:
        err_msg.append('The name need to set.')
        res = False
    if action == 'add' and not module.params['interface']:
        err_msg.append('The interface need to set.')
        res = False
    if action == 'add' and not module.params['pooltype'] and not module.params['pooltype']:
        err_msg.append('The ip or ipv6 must be set.')
        res = False
    if action == 'add' and not module.params['ipmin'] and not module.params['ipmin']:
        err_msg.append('The ipstart must be set.')
        res = False
    if action == 'add' and not module.params['ipmax'] and not module.params['ipmax']:
        err_msg.append('The ipend must be set.')
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
        natpool_name=dict(type='str', required=True),
        name=dict(type='str'),
        interface=dict(type='str'),
        pooltype=dict(type='str'),
        ipmin=dict(type='str'),
        ipmax=dict(type='str'),
        vdom=dict(type='str'),
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
        code, response = add_nat_pool(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_nat_pool(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_nat_pool(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            code, response = edit_nat_pool(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_nat_pool(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
            code, response = delete_nat_pool(module, connection)
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
