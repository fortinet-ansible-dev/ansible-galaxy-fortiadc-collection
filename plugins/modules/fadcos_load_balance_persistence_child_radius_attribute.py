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
module: fadcos_load_balance_persistence_child_radius_attribute
"""

EXAMPLES = """
"""

RETURN = """
"""


obj_url = '/api/load_balance_persistence_child_radius_attribute'

before = {}
after = {}
rep_dict = {
    'name': 'pkey',
    'id': '_id',
    'id_list': 'mkeys',
}

def module_err_exit(module, mesg):
    result = {}
    result['err_msg'] = mesg
    result['failed'] = True
    result['changed'] = False
    module.exit_json(**result)

check_mode_enabled = False
def update_url(module, connection, url):
    if is_vdom_enable(connection):
        return url + '?vdom=' + module.params['vdom'] + '&pkey=' + module.params['name']
    else:
        return url + '?pkey=' + module.params['name']

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
    url = update_url(module, connection, obj_url)
    code, response = send_request(url, payload, connection, 'POST')
    return code, response


def edit_obj(module, payload, connection):
    url = update_url(module, connection, obj_url) + '&mkey=' + payload['mkey']
    code, response = send_request(url, payload, connection, 'PUT')

    return code, response


def get_obj(module, connection):

    payload = {}
    url = update_url(module, connection, obj_url)
    if module.params['id'] is not None:
        url += '&mkey=' + module.params['id']
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    names = module.params['id_list']
    after['deleted'] = names
    vdom = module.params['vdom']
    payload = {
    'mkeys': module.params['id_list'],
    } 
    url = update_url(module, connection, obj_url + '/batch_remove')
    if check_mode_enabled == False:
        code, response = send_request(url, payload, connection, 'POST')
    else:
        code = 0
        response = "Check mode: change detected."
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

    if action != 'add' and action != 'get' and action != 'edit' and action != 'remove' and action != 'delete':
        res = False
        err_msg.append('The '+ action + 'is not supported.')
    if is_vdom_enable(connection) and not module.params['vdom']:
        err_msg.append('The vdom is enable in system setting, vdom must be set.')
        res = False
    elif is_vdom_enable(connection) and module.params['vdom'] and not is_user_in_vdom(connection, module.params['vdom']):
        err_msg.append('The user can not access the vdom ' + module.params['vdom'])
        res = False

    return res, err_msg

def main():
    global check_mode_enabled
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str', required=True),
        type=dict(type='str', default='1-user-name'),
        id=dict(type='str', default='1'),
        id_list=dict(type='list'),
        vdom=dict(type='str'),
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if,
                           supports_check_mode=True)
    connection = Connection(module._socket_path)

    if module.check_mode:
        check_mode_enabled = True
    action = module.params['action']
    result = {}
    param_pass, param_err = param_check(module, connection)
    module.params.pop('action')

    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
        module.exit_json(**result)

    code, data = get_obj(module, connection)
    if action == 'add':
        if isinstance(data, dict) and 'payload' in data and data['payload'] and isinstance(data['payload'], dict):
            result['res'] = "Duplicated entry detected."
        else:
            code, response = add_obj(module, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'get':
        result['res'] = data
    elif action == 'edit':
        if isinstance(data, dict) and 'payload' in data and data['payload'] and isinstance(data['payload'], dict):
            res, new_data = needs_update(module, data['payload'])
        else:
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_obj(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete' or action == 'remove' :
        if isinstance(data, dict) and 'payload' in data and data['payload']:
            code, response = delete_obj(module, connection)
            if check_mode_enabled == False and 'payload' in response.keys() and response['payload'] and type(response['payload']) is int:
                response['payload'] = 0
            result['res'] = response
            result['changed'] = True
        else:
            result['changed'] = False
            result['res'] = "Entry to delete not found."
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


    module.exit_json(**result)


if __name__ == '__main__':
    main()
