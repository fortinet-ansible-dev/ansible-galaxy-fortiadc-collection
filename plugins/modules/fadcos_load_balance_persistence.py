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
module: fadcos_load_balance_persistence
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/load_balance_persistence'

edit_dict = {
}

def update_payload(module):
    payload = {
    'mkey': module.params['name'],
    'ipv4-maskbits': module.params['ipv4_maskbits'],
    'ipv6-maskbits': module.params['ipv6_maskbits'],
    'timeout': module.params['timeout'],
    'type': module.params['type'],
    'match-across-servers': module.params['match_across_virtual_servers'],
    'keyword': module.params['keyword'],
    'sess_kw_type': module.params['sess_kw_type'],
    'cookie_domain': module.params['cookie_domain'],
    'cookie_httponly': module.params['cookie_httponly'],
    'cookie_secure': module.params['cookie_secure'],
    'cookie_samesite': module.params['cookie_samesite'],
    'cookie_custom_attr': module.params['cookie_custom_attr'],
    'match-across-servers': module.params['match_across_servers'],
    'override-connection-limit': module.params['override_connection_limit'],
    'radius-attribute-relation': module.params['radius_attribute_relation'],
    'iso8583_bitmap-relation': module.params['iso8583_bitmap_relation'],
    'keyvalue-relation': module.params['keyvalue_relation'],
    'mkeys': module.params['names'],
    }
    if payload['cookie_custom_attr'] == 'enable':
       payload['cookie_custom_attr_val'] = module.params['cookie_custom_attr_val']

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
    payload = update_payload(module)
    url = update_url(module, connection, obj_url)

    return request_obj(url, payload, connection, 'POST')

def edit_obj(module, connection):
    payload = update_payload(module)
    if is_vdom_enable(connection):
        url = obj_url + '?vdom=' + module.params['vdom'] + '&mkey=' + payload['mkey']
    else:
        url = obj_url + '?mkey=' + payload['mkey']

    return request_obj(url, payload, connection, 'PUT')

def remove_obj(module, connection):
    payload =update_payload(module)
    url = update_url(module, connection, obj_url + '/batch_remove')

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
        type=dict(type='str'),
        timeout=dict(type='int', default='300'),
        ipv4_maskbits=dict(type='str', default='32'),
        ipv6_maskbits=dict(type='str', default='128'),
        match_across_virtual_servers=dict(type='str', default='disable'),
        names=dict(type='list'),
        keyword=dict(type='str'),
        sess_kw_type=dict(type='str', default='auto'),
        cookie_domain=dict(type='str', default=''),
        cookie_httponly=dict(type='str', default='disable'),
        cookie_secure=dict(type='str', default='disable'),
        cookie_samesite=dict(type='str', default='nothing'),
        cookie_custom_attr=dict(type='str', default='disable'),
        cookie_custom_attr_val=dict(type='str'),
        match_across_servers=dict(type='str', default='disable'),
        override_connection_limit=dict(type='str', default='disable'),
        radius_attribute_relation=dict(type='str', default='AND'),
        iso8583_bitmap_relation=dict(type='str', default='OR'),
        keyvalue_relation=dict(type='str', default='AND'),
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
