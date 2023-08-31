
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
module: fadcos_load_balance_persistence_child_radius_attribute
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/load_balance_persistence_child_radius_attribute'

edit_dict = {
}

def update_payload(module):
    payload = {
    'pkey': module.params['name'],
    'mkey': module.params['id'],
    'type': module.params['type'],
    '_id': module.params['id'],
    'mkeys': module.params['id_list'],
    }

    return payload

def update_url(module, connection, url):
    if is_vdom_enable(connection):
        return url + '?vdom=' + module.params['vdom'] + '&pkey=' + module.params['name']
    else:
        return url + '?pkey=' + module.params['name']

def get_obj(module, connection):
    payload = {}
    pkey = module.params['name']
    url = update_url(module, connection, obj_url)

    return request_obj(url, payload, connection, 'GET')

def add_obj(module, connection):
    payload = update_payload(module)
    url = update_url(module, connection, obj_url)

    return request_obj(url, payload, connection, 'POST')

def edit_obj(module, connection):
    payload = update_payload(module)
    url = update_url(module, connection, obj_url) + '&mkey=' + payload['mkey']

    return request_obj(url, payload, connection, 'PUT')

def remove_obj(module, connection):
    payload = update_payload(module)
    url = url = update_url(module, connection, obj_url + '/batch_remove')

    return request_obj(url, payload, connection, 'POST')

def request_obj(url, payload, connection, action):
    code, response = connection.send_request(url, payload, action)

    return code, response

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if action != 'add' and action != 'get' and action != 'edit' and action != 'remove':
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
    elif action == 'edit':
        code, response = edit_obj(module, connection)
        result['changed'] = True
        result['res'] = response
    elif action == 'remove':
        code, response = remove_obj(module, connection)
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
