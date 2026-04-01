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

before = {}
after = {}

rep_dict = {
}

obj_url = '/api/system_time_manual'
edit_url = '/api/system_time_ntp?mkey=-1'

edit_dict = {
}

def update_payload(module):
    payload = {
    'ntpsync': module.params['ntpsync'],
    'syncinterval': module.params['syncinterval'],
    }

    return payload


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

def get_obj(module, connection):
    payload = {}
    url = obj_url

    return request_obj(url, payload, connection, 'GET')

def edit_obj(module, new_data, connection):
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
        ntpsync=dict(type='str'),
        syncinterval=dict(type='str'),
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_msg = param_check(module, connection)
    code, response = get_obj(module, connection)
    if not param_pass:
        result['failed'] = True
        result['err_msg'] = param_msg
    elif action == 'edit':
        data = response
        if isinstance(data, dict) and 'payload' in data and data['payload'] and isinstance(data['payload'], dict):
            res, new_data = needs_update(module, data['payload'])
        else:
            res = False
            result['err_msg'] = 'Entry not found.'
        code, response = edit_obj(module, new_data, connection)
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
