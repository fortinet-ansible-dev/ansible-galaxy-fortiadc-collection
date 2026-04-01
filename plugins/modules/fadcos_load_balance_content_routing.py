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


obj_url = '/api/load_balance_content_routing'


before = {}
after = {}
rep_dict = {
    'name': 'mkey',
    'packet_fwd_method': 'packet-fwd-method',
    'schedule_list': 'schedule-list',
    'schedule_pool_list': 'schedule-pool-list',
    'source_pool_list': 'source-pool-list',
    'names': 'mkeys',
}


def module_err_exit(module, mesg):
    result = {}
    result['err_msg'] = mesg
    result['failed'] = True
    result['changed'] = False
    module.exit_json(**result)

check_mode_enabled = False

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
    url = obj_url
    if is_vdom_enable(connection):
        url += '?vdom=' + vdom
    code, response = send_request(url, payload, connection, 'POST')
    return code, response


def edit_obj(module, payload, connection):
    name = module.params['name']
    vdom = module.params['vdom']
    url = obj_url
    if name:
        url += '?mkey=' + name
    else:
        module_err_exit(module, 'edit action needs the parameter \'name\' not to be empty.')
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        if name:
            url += '&vdom=' + vdom
        else:
            url += '?vdom=' + vdom

    code, response = send_request(url, payload, connection, 'PUT')

    return code, response


def get_obj(module, connection):
    name = module.params['name']
    vdom = module.params['vdom']
    payload = {}
    url = obj_url
    if name:
        url = obj_url + '?mkey=' + name
    else:
        url = obj_url
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        if name:
            url += '&vdom=' + vdom
        else:
            url += '?vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    names = module.params['names']
    after['deleted'] = names
    vdom = module.params['vdom']
    payload = {
    'mkeys': module.params['names'],
    } 
    url = obj_url + '/batch_remove'
    if not names:
        module_err_exit(module, 'delete action needs the parameter \'names\' not to be empty.')
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom
        
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
        if params[key] is not None and len(str(params[key]))!=0:
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
        err_msg.append('The user can not accsee the vdom ' + module.params['vdom'])
        res = False

    return res, err_msg

def main():
    global check_mode_enabled
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        connection_pool_inherit=dict(type='str', default='enable'),
        packet_fwd_method=dict(type='str', default='inherit'),
        type=dict(type='str', default='l4-content-routing'),
        # ip=dict(type='str',default='0.0.0.0/0'),
        # ip6=dict(type='str',default='::/0'),
        ip=dict(type='str'),
        ip6=dict(type='str'),
        pool=dict(type='str', default='rs_pool'),
        method_inherit=dict(type='str', default='enable'),
        persistence_inherit=dict(type='str', default='enable'),
        method=dict(type='str', default=''),
        persistence=dict(type='str', default=''),
        comments=dict(type='str'),
        schedule_list=dict(type="str", default='disable'),
        schedule_pool_list=dict(type="str"),
        source_pool_list=dict(type="str"),
        names=dict(type='list'),
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
    elif action == 'delete' or action == 'remove':
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
