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
module: fadcos_real_server_pool
description:
  - Configure real server pool on FortiADC devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""


def add_rs_pool(module, connection):
    name = module.params['name']
    iptype = module.params['iptype']
    healthcheck = module.params['healthcheck']
    health_check_relationship = module.params['health_check_relationship']
    health_check_list = list_to_str(module.params['health_check_list'])
    rs_profile = module.params['rs_profile']
    vdom = module.params['vdom']

    payload = {'mkey': name,
               'pool_type': iptype,
               'health_check': healthcheck,
               'health_check_relationship': health_check_relationship,
               'health_check_list': health_check_list,
               'rs_profile': rs_profile
               }

    url = '/api/load_balance_pool'
    if is_vdom_enable(connection):
        url += '?vdom=' + vdom

    code, response = connection.send_request(url, payload)

    return code, response


def edit_rs_pool(module, payload, connection):
    name = module.params['name']
    vdom = module.params['vdom']
    url = '/api/load_balance_pool?mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_rs_pool(module, connection):
    name = module.params['name']
    vdom = module.params['vdom']
    payload = {}
    url = '/api/load_balance_pool'
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


def delete_rs_pool(module, connection):
    name = module.params['name']
    vdom = module.params['vdom']
    payload = {}
    url = '/api/load_balance_pool?mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False

    if module.params['iptype'] and module.params['iptype'] != data['pool_type']:
        data['pool_type'] = module.params['iptype']
        res = True
    if module.params['healthcheck'] and module.params['healthcheck'] != data['health_check']:
        data['health_check'] = module.params['healthcheck']
        res = True
    if module.params['health_check_relationship'] and module.params['health_check_relationship'] != data['health_check_relationship']:
        data['health_check_relationship'] = module.params['health_check_relationship']
        res = True
    if list_need_update(module.params['health_check_list'], data['health_check_list']):
        data['health_check_list'] = list_to_str(
            module.params['health_check_list'])
        res = True
    if module.params['rs_profile'] and module.params['rs_profile'] != data['rs_profile']:
        data['rs_profile'] = module.params['rs_profile']
        res = True
    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'edit' or action == 'delete') and not module.params['name']:
        err_msg.append('The name need to set.')
        res = False
    if action == 'add' and not module.params['iptype']:
        err_msg.append('The iptype need to set.')
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
        iptype=dict(type='str'),
        healthcheck=dict(type='str', default='disable'),
        health_check_relationship=dict(type='str', default='AND'),
        health_check_list=dict(type='list'),
        rs_profile=dict(type='str', default='NONE'),
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
        code, response = add_rs_pool(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_rs_pool(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_rs_pool(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            code, response = edit_rs_pool(module, new_data, connection)
            result['changed'] = True
            result['res'] = response
    elif action == 'delete':
        code, data = get_rs_pool(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
            code, response = delete_rs_pool(module, connection)
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
