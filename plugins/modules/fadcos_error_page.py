#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2023/04/06

from __future__ import (absolute_import, division, print_function)
import json
import urllib3
import sys
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_vdom_enable
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import prepare_multipart
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import prepare_multipart_base64

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: fadcos_error_page
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/load_balance_error_page'
upload_url = '/api/upload/error_page'

edit_dict = {
}

def update_payload(module):
    payload = {
    'vpath': module.params['vpath'],
    'mkey': module.params['name'],
    'local_pc': module.params['srcfile'],
    'mkeys': module.params['names'],
    }

    return payload

def update_url(module, url):
    if module.params['vdom']:
        return url + '?vdom=' + module.params['vdom']
    else:
        return url

def add_obj(module, connection):
    payload = update_payload(module)
    url = update_url(module, upload_url)
    if sys.version_info >= (3,6):
        data = {
                'vpath': payload['vpath'],
                'mkey': payload['mkey'],
                'local_pc': payload['local_pc'],
                'errorPageFile': {
                    'filename': payload['local_pc'],
                    },
                'Content-Transfer-Encoding' : "base64",
                }
        content_type, b_data = prepare_multipart_base64(data)
    else:
        data = {
                'vpath': payload['vpath'],
                'mkey': payload['mkey'],
                'local_pc': payload['local_pc'],
                'errorPageFile': "",
                'filename': (payload['local_pc'], open(payload['local_pc'], 'r', 'cp950').read()),
                }
        b_data, content_type = urllib3.encode_multipart_formdata(data)
    
    headers = {
        'Content-type': content_type,
    }
    code, response = connection.send_url_request(url, b_data.decode('ascii'), headers=headers)
    return code, response

def get_obj(module, connection):
    payload = {}
    url = update_url(module, obj_url)

    return request_obj(url, payload, connection, 'GET')

def edit_obj(module, connection):
    payload = update_payload(module)
    if module.params['vdom']:
        url = obj_url + '?vdom=' + module.params['vdom'] + '&mkey=' + payload['mkey']
    else:
        url = obj_url + '?mkey=' + payload['mkey']

    return request_obj(url, payload, connection, 'PUT')

def remove_obj(module, connection):
    url = update_url(module, obj_url + '/batch_remove')
    payload = update_payload(module)

    return request_obj(url, payload, connection, 'POST')

def request_obj(url, payload, connection, action):
    code, response = connection.send_request(url, payload, action)

    return code, response

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []
    if action != 'add' and action != 'get' and action != 'remove' and action != 'edit':
        res = False
        err_msg.append('The '+ action + 'is not supported.')

    return res, err_msg

def vdom_check(module, connection):
    res = True
    err_msg = []
    if module.params['action'] != 'add':
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
        name=dict(type='str'),
        srcfile=dict(type='str'),
        names=dict(type='list'),
        vpath=dict(type='str', default='/fortiadc_error_page/'),
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
    vdom_pass, vdom_msg = vdom_check(module, connection)
    if not param_pass:
        result['failed'] = True
        result['err_msg'] = param_msg
    elif not vdom_pass:
        result['failed'] = True
        result['err_msg'] = vdom_msg
    elif action == 'add':
        code, response = add_obj(module, connection)
        result['changed'] = True
        result['res'] = response
    elif action == 'edit':
        code, response = edit_obj(module, connection)
        result['changed'] = True
        result['res'] = response
    elif action == 'get':
        code, response = get_obj(module, connection)
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
