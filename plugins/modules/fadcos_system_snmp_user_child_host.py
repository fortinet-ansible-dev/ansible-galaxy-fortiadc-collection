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
module: system_snmp_user_child_host
"""

EXAMPLES = """
"""

RETURN = """
"""

before = {}
after = {}

obj_url = '/api/system_snmp_user_child_host'

rep_dict = {
    'snmp_name': 'pkey',
    'id': 'mkey',
    'id_list': 'mkeys',
}

def module_err_exit(module, mesg):
    result = {}
    result['err_msg'] = mesg
    result['failed'] = True
    result['changed'] = False
    module.exit_json(**result)

check_mode_enabled = False

def update_payload(module):
    payload = {
    'name': module.params['name'],
    'pkey': module.params['snmp_name'],
    'ip': module.params['ip'],
    'mkey': module.params['id'],
    'mkeys': module.params['id_list'],
    'host_type': module.params['host_type'],
    }

    return payload

def send_request(url, payload, connection, action):
    if check_mode_enabled:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, action)
    return code, response

def add_obj(module, connection):
    after['added'] = module.params
    payload = {}
    params = module.params
    vdom = module.params['vdom']
    for key in params.keys():
        if params[key] is not None:
            data_key = None
            if key in rep_dict.keys():
                data_key = rep_dict[key]
            else:
                data_key = key #This key's value is not changed. 
            payload[data_key] = params[key] 
    url = obj_url + '?pkey=' + module.params['snmp_name']
    if is_vdom_enable(connection) and module.params['vdom']:
        url += '&vdom=' + vdom
    code, response = send_request(url, payload, connection, 'POST')
    return code, response


def edit_obj(module, payload, connection):
    pkey = module.params['snmp_name']
    mkey = module.params['id']
    vdom = module.params['vdom']
    url = obj_url
    if pkey and mkey:
        url = obj_url + '?pkey=' + pkey + '&mkey=' + mkey
    else:
        module_err_exit(module, 'edit action needs the parameter \'snmp_name\' and \'id\' not to be empty.')
    if is_vdom_enable(connection) and module.params['vdom']:
        vdom = module.params['vdom']
        if pkey or mkey:
            url += '&vdom=' + vdom
        else:
            url += '?vdom=' + vdom

    code, response = send_request(url, payload, connection, 'PUT')

    return code, response


def get_obj(module, connection):
    snmp_name = module.params['snmp_name']
    id = module.params['id']
    vdom = module.params['vdom']
    payload = {}
    if snmp_name:
        url = obj_url + '?pkey=' + snmp_name
        if id:
            url += '&mkey=' + id
    else:
        url = obj_url
    if is_vdom_enable(connection) and module.params['vdom']:
        vdom = module.params['vdom']
        if snmp_name:
            url += '&vdom=' + vdom
        else:
            url += '?vdom=' + vdom           
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    after['deleted'] = module.params
    vdom = module.params['vdom']
    url = obj_url
    payload = update_payload(module)
    pkey = payload['pkey']
    url = obj_url + '/batch_remove?pkey=' + pkey
    if is_vdom_enable(connection) and module.params['vdom']:
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = send_request(url, payload, connection, 'POST')
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
    res = False
    action = module.params['action']
    err_msg = []
    if (action == 'get' or action == 'add' or action == 'remove' or action == 'edit'):
        res = True
    else:
        res = False
        err_msg.append('action \''+action + '\' is not supported')

    return res, err_msg

def main():
    global check_mode_enabled
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        ip=dict(type='str'),
        snmp_name=dict(type='str', required=True),
        vdom=dict(type='str'),
        id=dict(type='str'),
        id_list=dict(type='list'),
        host_type=dict(type='str', default='any'),
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_msg = param_check(module, connection)
    if not param_pass:
        result['failed'] = True
        result['err_msg'] = param_msg
        module.exit_json(**result)
    code, data = get_obj(module, connection)
    if action == 'get':
        result['res'] = data
    elif action == 'add':
        code, response = add_obj(module, connection)
        result['changed'] = True
        result['res'] = response
    elif action == 'remove':
        code, response = delete_obj(module, connection)
        if 'payload' in response.keys() and response['payload'] and type(response['payload']) is int and response['payload'] < 0:
            response['payload'] = 0
        result['changed'] = True
        result['res'] = response
    elif action == 'edit':
        if 'payload' in data.keys() and data['payload'] and isinstance(data['payload'], dict):
            res, new_data = needs_update(module, data['payload'])
        else:
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_obj(module, new_data, connection)
            result['res'] = response
            result['changed'] = True

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
    else:
        if module.check_mode:
           result['res'] = 'Check mode: no changes detected.'  

    module.exit_json(**result)


if __name__ == '__main__':
    main()
