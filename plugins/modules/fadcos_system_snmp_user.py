
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

obj_url = '/api/system_snmp_user'

edit_dict = {
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

def get_obj(module, connection):
    payload = {}
    url = obj_url

    return request_obj(url, payload, connection, 'GET')

def add_obj(module, connection):
    url = obj_url
    payload = update_payload(module)

    return request_obj(url, payload, connection, 'POST')

def remove_obj(module, connection):
    url = obj_url + '/batch_remove'
    payload = update_payload(module)

    return request_obj(url, payload, connection, 'POST')

def edit_obj(module, connection):
    payload = update_payload(module)
    mkey = payload['mkey']
    url = obj_url + '?mkey=' + mkey

    return request_obj(url, payload, connection, 'PUT')

def request_obj(url, payload, connection, action):
    code, response = connection.send_request(url, payload, action)

    return code, response

def param_check(module, connection):
    res = False
    action = module.params['action']
    err_msg = ''
    if (action == 'get' or action == 'add' or action == 'remove' or action == 'edit'):
        res = True
    else:
        res = False
        err_msg = action + 'is not supported'

    return res, err_msg

def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
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
        result['res'] = response
    elif action == 'add':
        code, response = add_obj(module, connection)
        result['changed'] = True
        result['res'] = response
    elif action == 'remove':
        code, response = remove_obj(module, connection)
        result['changed'] = True
        result['res'] = response
    elif action == 'edit':
        code, response = edit_obj(module, connection)
        result['changed'] = True
        result['res'] = response

    if 'res' in result.keys() and type(result['res']) is dict\
            and type(result['res']['payload']) is int and result['res']['payload'] < 0:
        result['err_msg'] = get_err_msg(connection, result['res']['payload'])
        result['changed'] = False
        result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
