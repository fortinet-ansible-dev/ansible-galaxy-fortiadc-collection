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
module: fadcos_load_balance_content_routing
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/load_balance_content_routing'

edit_dict = {
}

def update_payload(module):
    payload = {
    'mkey': module.params['name'],
    'connection_pool_inherit': module.params['connection_pool_inherit'],
    'packet-fwd-method': module.params['packet_fwd_method'],
    'type': module.params['type'],
    'ip': module.params['ip'],
    'ip6': module.params['ip6'],
    'pool': module.params['pool'],
    'method_inherit': module.params['method_inherit'],
    'persistence_inherit': module.params['persistence_inherit'],
    'method': module.params['method'],
    'persistence': module.params['persistence'],
    'comments': module.params['comments'],
    'schedule-list': module.params['schedule_list'],
    'schedule-pool-list': module.params['schedule_pool_list'],
    'source-pool-list': module.params['source_pool_list'],
    'mkeys': module.params['names'],
    }

    return payload

def update_url(module, connection, url):
    if is_vdom_enable(connection):
        return url + '?vdom=' + module.params['vdom']
    else:
        return url

def get_obj(module, connection):
    payload = {}
    url = update_url(module, connection, obj_url)

    return request_obj(url, payload, connection, 'GET')

def add_obj(module, connection):
    url = update_url(module, connection, obj_url)
    payload = update_payload(module)

    return request_obj(url, payload, connection, 'POST')

def edit_obj(module, connection):
    payload = update_payload(module)
    if is_vdom_enable(connection):
        url = obj_url + '?vdom=' + module.params['vdom'] + '&mkey=' + payload['mkey']
    else:
        url = obj_url + '?mkey=' + payload['mkey']

    return request_obj(url, payload, connection, 'PUT')

def remove_obj(module, connection):
    url = update_url(module, connection, obj_url + '/batch_remove')
    payload = update_payload(module)
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
        err_msg.append('The user can not accsee the vdom ' + module.params['vdom'])
        res = False

    return res, err_msg

def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        connection_pool_inherit=dict(type='str', default='enable'),
        packet_fwd_method=dict(type='str', default='inherit'),
        type=dict(type='str', default='l4-content-routing'),
        ip=dict(type='str',default='0.0.0.0/0'),
        ip6=dict(type='str',default='::/0'),
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
