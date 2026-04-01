#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec, is_vdom_enable, get_err_msg
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fadcos_vdom
short_description: Manage FortiADC VDOM by RESTful API
description:
  - Manage vdom on FortiADC devices including creating, updating, removing vdom objects,
    All operations are performed via RESTful API.
version_added: "2.8"
author: ""
options:
"""

EXAMPLES = """

"""

RETURN = """
"""

before = {}
after = {}


def add_vdom(module, connection):
    after['added'] = module.params
    name = module.params['name']

    payload = {'mkey': name}
    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request('/api/vdom', payload)

    return code, response


'''
#/api/system_vdom/get_vdom_rlimit?vdom=root&pkey=root
def edit_vdom(module, payload, connection):
    name = module.params['name']
    url = '/api/vdom?mkey=' + name
    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'PUT')

    return code, response
'''


def get_vdom(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/vdom'

    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_vdom(module, connection):
    after['deleted'] = module.params
    name = module.params['name']
    payload = {}
    url = '/api/vdom?mkey=' + name
    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str', required=True),
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True,
                           required_if=required_if)
    connection = Connection(module._socket_path)
    action = module.params['action']
    result = {}
    if not is_vdom_enable(connection):
        result['err_msg'] = 'vdom is disable in system setting, please check'
        result['failed'] = True
    elif action == 'add':
        code, response = add_vdom(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_vdom(module, connection)
        result['res'] = response
    elif action == 'delete':
        code, response = delete_vdom(module, connection)
        result['res'] = response
        if isinstance(response,dict) and 'payload' in response.keys() and type(response['payload']) is int and response['payload'] < 0:
            response['payload'] = 0
            result['changed'] = False         

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
