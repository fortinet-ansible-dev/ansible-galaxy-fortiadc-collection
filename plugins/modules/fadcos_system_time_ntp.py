#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2023/04/06

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
module: fadcos_system_time_ntp
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/system_time_manual'

edit_dict = {
}

def update_payload(module):
    payload = {
    'ntpserver': module.params['ntpserver'],
    'ntpsync': module.params['ntpsync'],
    'syncinterval': module.params['syncinterval'],
    }

    return payload

def get_obj(module, connection):
    payload = {}
    url = obj_url

    return request_obj(url, payload, connection, 'GET')

def edit_obj(module, connection):
    url = obj_url
    payload = update_payload(module)

    return request_obj(url, payload, connection, 'PUT')

def request_obj(url, payload, connection, action):
    code, response = connection.send_request(url, payload, action)

    return code, response

def param_check(module, connection):
    res = False
    action = module.params['action']
    err_msg = ''
    if (action == 'get' or action == 'edit'):
        res = True
    else:
        res = False
        err_msg = action + 'is not supported'

    return res, err_msg

def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        ntpserver=dict(type='str'),
        ntpsync=dict(type='str', default='enable'),
        syncinterval=dict(type='str', default='60'),
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_msg = param_check(module, connection)
    if not param_pass:
        result['failed'] = True
        result['err_msg'] = param_msg
    elif action == 'get':
        code, response = get_obj(module, connection)
    elif action == 'edit':
        code, response = edit_obj(module, connection)
        result['changed'] = True
    result['res'] = response
    
    ntpsync = module.params['ntpsync']
    if action == 'edit' and ntpsync == 'disable' and len(result['res']) == 0:
        module.exit_json(**result)

    if 'res' in result.keys() and type(result['res']) is dict\
            and type(result['res']['payload']) is int and result['res']['payload'] < 0:
        result['err_msg'] = get_err_msg(connection, result['res']['payload'])
        result['changed'] = False
        result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
