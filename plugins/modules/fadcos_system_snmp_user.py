
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
module: fadcos_system_snmp_user
"""

EXAMPLES = """
"""

RETURN = """
"""

before = {}
after = {}

obj_url = '/api/system_snmp_user'

rep_dict = {
    'name': 'mkey',
    'names': 'mkeys',
}

def update_payload(module):
    payload = {
    'mkey': module.params['name'],
    'security_level': module.params['security_level'],
    'auth_proto': module.params['auth_proto'],
    'auth_pwd': module.params['auth_pwd'],
    'privacy_proto': module.params['privacy_proto'],
    'privacy_pwd': module.params['privacy_pwd'],
    'query_port': module.params['query_port'],
    'query_status': module.params['query_status'],
    'status': module.params['status'],
    'events': module.params['events'],
    'trap_local_port': module.params['trap_local_port'],
    'trap_remote_port': module.params['trap_remote_port'],
    'trap_status': module.params['trap_status'],
    'mkeys': module.params['names'],
    }

    return payload


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

def get_obj(module, connection):
    payload = {}
    url = obj_url
    mkey = module.params['name']
    if mkey:
        url = obj_url + '?mkey=' + mkey
    else: 
        url = obj_url

    if is_vdom_enable(connection) and module.params['vdom']:
        if mkey:
            url += '&vdom=' + module.params['vdom']
        else:
            url += '?vdom=' + module.params['vdom']    
    return connection.send_request(url, payload, 'GET')

def add_obj(module, connection):
    after['added'] = module.params
    vdom = module.params['vdom']
    url = obj_url
    payload = update_payload(module)
    if is_vdom_enable(connection) and module.params['vdom']:
        url += '?vdom=' + vdom
    return send_request(url, payload, connection, 'POST')

def remove_obj(module, connection):
    after['deleted'] = module.params['names']
    url = obj_url + '/batch_remove'
    payload = update_payload(module)
    if is_vdom_enable(connection) and module.params['vdom']:
        url += '?vdom=' + module.params['vdom']
    return send_request(url, payload, connection, 'POST')

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


def edit_obj(module, payload, connection):
    mkey = payload['mkey']
    if mkey:
        url = obj_url + '?mkey=' + mkey
    else: 
        return module_err_exit(module, 'edit action needs \'name\' not to be empty.')
    if is_vdom_enable(connection) and module.params['vdom']:
        url += '&vdom=' + module.params['vdom']
    
    return send_request(url, payload, connection, 'PUT')


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
        vdom=dict(type='str'),
        security_level=dict(type='str'),
        auth_proto=dict(type='str'),
        auth_pwd=dict(type='str'),
        privacy_proto=dict(type='str'),
        privacy_pwd=dict(type='str'),
        query_port=dict(type='str', default='161'),
        query_status=dict(type='str', default='enable'),
        status=dict(type='str'),
        events=dict(type='str', default='cpu mem logdisk platform'),
        trap_local_port=dict(type='str', default='162'),
        trap_remote_port=dict(type='str', default='162'),
        trap_status=dict(type='str', default='enable'),
        names=dict(type='list'),
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
        code, response = remove_obj(module, connection)
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

    module.exit_json(**result)


if __name__ == '__main__':
    main()
