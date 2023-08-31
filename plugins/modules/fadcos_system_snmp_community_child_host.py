
#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2023/05/25

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
module: system_snmp_community_child_host
options:
    action:
        description: Type of action to perform on the object
        required: Yes
        type: String
        options: add, get, remove, edit

    snmp_id:
        description: SNMP ID
        type: String

    ip:
        description: IP Address
        type: String
        Example: 192.0.0.1/24

    id:
        description: Host ID
        type: String

    id_list:
        description: Host ID List
        type: List
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/system_snmp_community_child_host'

edit_dict = {
}

def update_payload(module):
    payload = {
    'name': module.params['name'],
    'pkey': module.params['snmp_id'],
    'ip': module.params['ip'],
    'mkey': module.params['id'],
    'mkeys': module.params['id_list'],
    }

    return payload

def get_obj(module, connection):
    payload = update_payload(module)
    pkey = payload['pkey']
    url = obj_url + '?pkey=' + pkey

    return request_obj(url, payload, connection, 'GET')

def add_obj(module, connection):
    payload = update_payload(module)
    pkey = payload['pkey']
    url = obj_url + '?pkey=' + pkey

    return request_obj(url, payload, connection, 'POST')

def remove_obj(module, connection):
    payload = update_payload(module)
    pkey = payload['pkey']
    url = obj_url + '/batch_remove?pkey=' + pkey

    return request_obj(url, payload, connection, 'POST')

def edit_obj(module, connection):
    payload = update_payload(module)
    pkey = payload['pkey']
    mkey = payload['mkey']
    url = obj_url + '?pkey=' + pkey + '&mkey=' + mkey

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
        ip=dict(type='str'),
        snmp_id=dict(type='str', required=True),
        id=dict(type='str'),
        id_list=dict(type='list'),
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
