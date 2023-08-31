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
module: fadcos_route_static
description:
  - Configure static route on FortiADC devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""


def add_route_static(module, connection):
    route_id = module.params['route_id']
    desination = module.params['desination']
    gateway = module.params['gateway']
    distance = module.params['distance']
    vdom = module.params['vdom']

    payload = {'mkey': route_id,
               'dest': desination,
               'distance': distance,
               'gw': gateway,
               }

    url = '/api/router_static'
    if is_vdom_enable(connection):
        url += '?vdom=' + vdom

    code, response = connection.send_request(url, payload)

    return code, response


def edit_route_static(module, payload, connection):
    name = module.params['route_id']
    url = '/api/router_static?mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_route_static(module, connection):
    name = module.params['route_id']
    payload = {}
    url = '/api/router_static'
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


def delete_route_static(module, connection):
    name = module.params['route_id']
    payload = {}
    url = '/api/router_static?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False

    if module.params['desination'] and module.params['desination'] != data['dest']:
        data['dest'] = module.params['desination']
        res = True
    if module.params['gateway'] and module.params['gateway'] != data['gw']:
        data['gw'] = module.params['gateway']
        res = True
    if module.params['distance'] and module.params['distance'] != data['distance']:
        data['distance'] = module.params['distance']
        res = True
    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'edit' or action == 'delete') and not module.params['route_id']:
        err_msg.append('The route_id need to set.')
        res = False
    if module.params['route_id']:
        try:
            i = int(module.params['route_id'])
        except ValueError:
            err_msg.append('The route_id must be integer.')
            res = False
    if action == 'add' and not module.params['desination']:
        err_msg.append('The desination need to set.')
        res = False
    if action == 'add' and not module.params['gateway']:
        err_msg.append('The gateway must be set.')
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
        route_id=dict(type='str'),
        desination=dict(type='str'),
        gateway=dict(type='str'),
        distance=dict(type='str'),
        vdom=dict(type='str')
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = []
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
        code, response = add_route_static(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_route_static(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_route_static(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            code, response = edit_route_static(module, new_data, connection)
            result['changed'] = True
            result['res'] = response
    elif action == 'delete':
        code, data = get_route_static(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
            code, response = delete_route_static(module, connection)
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
