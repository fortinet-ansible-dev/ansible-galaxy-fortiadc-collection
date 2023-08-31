#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
import urllib3
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_global_admin
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import prepare_multipart
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fadcos_vm_license
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/upload/vmlicense'

rep_dict = {
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def add_obj(module, connection):
    payload1 = {}
    payload1['data'] = module.params

    # data1 = {
    #        'license': {
    #            'filename': payload1['data']['srcfile'],
    #        }
    # }
    data2 = {
        'license': "",
        'filename': (payload1['data']['srcfile'], open(payload1['data']['srcfile']).read()),
    }

    # content_type, b_data = prepare_multipart(data1)
    b_data, content_type = urllib3.encode_multipart_formdata(data2)

    headers = {
        'Content-type': content_type,
    }
    code, response = connection.send_url_request(obj_url, b_data.decode('ascii'), headers=headers)
    return code, response, headers, b_data.decode('ascii'),


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    # if is_vdom_enable(connection) and module.params['vdom'] is None:
    #    err_msg = 'vdom enable, vdom need to set'
    #    res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        srcfile=dict(type='str'),
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_err = param_check(module, connection)
    # if is_vdom_enable(connection) and param_pass:
    #    connection.change_auth_for_vdom(module.params['vdom'])

    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
    elif action == 'upload':
        code, response, h, b = add_obj(module, connection)
        result['res'] = response
        result['changed'] = True
        # result['h'] = h
        # result['b'] = b
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    if 'res' in result.keys() and type(result['res']) is dict\
            and type(result['res']['payload']) is int and result['res']['payload'] < 0:
        result['err_msg'] = get_err_msg(connection, result['res']['payload'])
        result['changed'] = False
        result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
