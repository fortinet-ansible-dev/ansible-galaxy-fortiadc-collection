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
module: fadcos_real_server
description:
  - Configure real server on FortiADC devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""


def add_rs(module, connection):
    name = module.params['name']
    status = module.params['status']
    ip = module.params['ip']
    ipv6 = module.params['ipv6']
    vdom = module.params['vdom']

    payload = {'mkey': name,
               'status': status,
               'address': ip,
               'address6': ipv6,
               }

    url = '/api/load_balance_real_server'
    if is_vdom_enable(connection):
        url += '?vdom=' + vdom

    code, response = connection.send_request(url, payload)

    return code, response


def edit_rs(module, payload, connection):
    name = module.params['name']
    url = '/api/load_balance_real_server?mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_rs(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/load_balance_real_server'
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


def delete_rs(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/load_balance_real_server?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False

    if module.params['status'] and module.params['status'] != data['status']:
        data['status'] = module.params['status']
        res = True
    if module.params['ip'] and module.params['ip'] != data['address']:
        data['address'] = module.params['ip']
        res = True
    if module.params['ipv6'] and module.params['ipv6'] != data['address6']:
        data['address6'] = module.params['ipv6']
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
    if action == 'add' and not module.params['ip'] and not module.params['ipv6']:
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
        ip=dict(type='str'),
        ipv6=dict(type='str', default='::'),
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
        code, response = add_rs(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_rs(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_rs(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            code, response = edit_rs(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_rs(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
            code, response = delete_rs(module, connection)
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
