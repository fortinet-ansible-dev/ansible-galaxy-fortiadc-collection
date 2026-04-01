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
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: fadcos_nat_pool
description:
  - Configure NAT pool on FortiADC devices via RESTful APIs.
"""

EXAMPLES = """
"""

RETURN = """
"""

before = {}
after = {}
rep_dict = {
    'iptype': 'pool_type',
    'ipstart': 'ip-start',
    'ipend': 'ip-end'
}


def add_nat_pool(module, connection):
    after['added'] = module.params
    name = module.params['name']
    interface = module.params['interface']
    iptype = module.params['iptype']
    ipstart = module.params['ipstart']
    ipend = module.params['ipend']
    vdom = module.params['vdom']

    payload = {'mkey': name,
               'interface': interface,
               'pool_type': iptype,
               }

    if iptype == 'ipv6':
        payload['ip6-start'] = ipstart
        payload['ip6-end'] = ipend
    else:
        payload['ip-start'] = ipstart
        payload['ip-end'] = ipend

    url = '/api/load_balance_ippool'
    if is_vdom_enable(connection):
        url += '?vdom=' + vdom

    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload)
    return code, response


def edit_nat_pool(module, payload, connection):
    name = module.params['name']
    vdom = module.params['vdom']
    url = '/api/load_balance_ippool'
    if name:
        url += '?mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        if name:
            url += '&vdom=' + vdom
        else:
            url += '?vdom=' + vdom

    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_nat_pool(module, connection):
    name = module.params['name']
    vdom = module.params['vdom']
    payload = {}
    if name:
        url = '/api/load_balance_ippool?mkey=' + name
    else:
        url = '/api/load_balance_ippool'
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        if name:
            url += '&vdom=' + vdom
        else:
            url += '?vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_nat_pool(module, connection):
    after['deleted'] = module.params
    name = module.params['name']
    vdom = module.params['vdom']
    payload = {}
    url = '/api/load_balance_ippool?mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    
    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'DELETE')
    return code, response


def combine_dict(src_dict, dst_dict):
    changed = False
    for key in dst_dict:
        if key in src_dict and src_dict[key] is not None and dst_dict[key] != src_dict[key]:
            dst_dict[key] = src_dict[key]
            changed = True

    return changed

def needs_update(module, data):
    res = False
    params = module.params
    for key in params.keys():
        if params[key] is not None:
            data_key = None
            if key in data.keys() and params[key] != data[key]:
                data_key = key 
            elif key in rep_dict.keys() and rep_dict[key] in data.keys() and params[key] != data[rep_dict[key]] :
                data_key = rep_dict[key]
            else:
                continue #This key's value is not changed. 
            if isinstance(params[key], str) and isinstance(data[data_key], str) and params[key].rstrip() == data[data_key].rstrip():
                continue #some sring values returned from API have trailing whitespace
            before[key] = data[data_key]
            after[key] = params[key]
            data[data_key] = params[key]
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
    if action == 'add' and not module.params['iptype'] and not module.params['iptype']:
        err_msg.append('The ip or ipv6 must be set.')
        res = False
    if action == 'add' and not module.params['ipstart'] and not module.params['ipstart']:
        err_msg.append('The ipstart must be set.')
        res = False
    if action == 'add' and not module.params['ipend'] and not module.params['ipend']:
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
        name=dict(type='str'),
        interface=dict(type='str'),
        iptype=dict(type='str'),
        ipstart=dict(type='str'),
        ipend=dict(type='str'),
        vdom=dict(type='str'),
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if,
                           supports_check_mode=True)
    connection = Connection(module._socket_path)

    action = module.params['action']
    result = {}
    param_pass, param_err = param_check(module, connection)
    module.params.pop('action')

    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
        module.exit_json(**result)

    code, data = get_nat_pool(module, connection)
    if action == 'add':
        if 'payload' in data.keys() and data['payload'] and isinstance(data['payload'], dict):
            result['res'] = "Duplicated entry detected."
        else:
            code, response = add_nat_pool(module, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'get':
        result['res'] = data
    elif action == 'edit':
        if 'payload' in data.keys() and data['payload'] and isinstance(data['payload'], dict):
            res, new_data = needs_update(module, data['payload'])
        else:
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_nat_pool(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        if 'payload' in data.keys() and data['payload'] and isinstance(data['payload'], dict):
            code, response = delete_nat_pool(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['changed'] = False
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    if 'res' in result.keys() and type(result['res']) is dict\
            and type(result['res']['payload']) is int and result['res']['payload'] < 0:
        result['err_msg'] = get_err_msg(connection, result['res']['payload'])
        result['changed'] = False
        result['failed'] = True
        if result['res']['payload'] == -15:
            result['failed'] = False

    if 'changed' in result.keys() and result['changed'] == True:
        result['diff'] = {
            'before': before,
            'after': after
        }
    else:
        if module.check_mode:
           result['res'] = 'Check mode: no changes detected.'  

    module.exit_json(**result)


if __name__ == '__main__':
    main()
