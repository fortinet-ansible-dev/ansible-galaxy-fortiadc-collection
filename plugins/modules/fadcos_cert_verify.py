#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2022/05/02

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_vdom_enable
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_to_str
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_need_update
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}

DOCUMENTATION = """
module: fadcos_cert_verify
description:
    Configure a certificate verification object on FortiADC devices via RESTful APIs
version_added: "v1.0.0"
author: asri@fortinet.com
options:
    action:
        description: Type of action to perform on the object
        required: Yes
        type: String
        default: N/A
    name:
        description: Certificate verification object name.
        required: Yes
        type: String
        default: N/A
    member_id:
        description: Certificate verification object member ID.
        required: Yes
        type: String
        default:
    ca:
        description: Select a CA.
        required: No
        type: String
        default: Fortinet_CA
    crl:
        description: Select a CRL.
        required: No
        type: String
        default: 
    ocsp:
        description: Select an OCSP.
        required: No
        type: String
        default: 
    vdom:
        description: VDOM name if enabled.
        required: Yes (if VDOM is enabled)
        type: String
        default: N/A
"""

EXAMPLES = """
- name:
  hosts: all
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Manage Certificate Verification Object
      fadcos_cert_verify:
        action: add_object
        name: test_object
    - name: Manage Certificate Verification Object Member
      fadcos_cert_verify:
        action: add_member
        name: test_object
        ca: Fortinet_CA
"""

RETURN = """
fadcos_cert_verify:
  description: The FortiADC certificate verification object created or updated.
  returned: always
  type: string
"""

def add_cert_verify_object(module, connection):

    payload = {'mkey': module.params['name']}

    url = '/api/system_certificate_certificate_verify'
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom

    code, response = connection.send_request(url, payload)
    return code, response

def add_cert_verify_object_member(module, connection):
    name = module.params['name']

    payload = {
        'ca': module.params['ca'],
        'crl': module.params['crl'],
        'ocsp': module.params['ocsp'],
        }

    url = '/api/system_certificate_certificate_verify_child_group_member?pkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload)
    return code, response

def get_cert_verify_object(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/system_certificate_certificate_verify'

    if name:
        url += '?mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        if name:
            url += '&vdom=' + vdom
        else:
            url += '?vdom=' + vdom

    code, response = connection.send_request(url, payload, 'GET')
    return code, response

def get_cert_verify_object_member(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/system_certificate_certificate_verify_child_group_member?pkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'GET')
    return code, response

def delete_cert_verify_object(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/system_certificate_certificate_verify?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')
    return code, response

def delete_cert_verify_object_member(module, connection):
    name = module.params['name']
    member_id = module.params['member_id']
    payload = {}
    url = '/api/system_certificate_certificate_verify_child_group_member?pkey=' + name + '&mkey=' + member_id

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')
    return code, response

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add_object' or action == 'delete_object' or action == 'add_member' or action == 'get_member' or action == 'delete_member') and not module.params['name']:
        err_msg.append('The certificate verification object name is required.')
        res = False
    if (action == 'delete_member') and not module.params['member_id']:
        err_msg.append('The certificate verification object member ID is required.')
        res = False
    if is_vdom_enable(connection) and not module.params['vdom']:
        err_msg.append('The vdom is enabled in system setting, vdom must be set.')
        res = False
    elif is_vdom_enable(connection) and module.params['vdom'] and not is_user_in_vdom(connection, module.params['vdom']):
        err_msg.append('The user can not access the vdom ' + module.params['vdom'])
        res = False

    return res, err_msg

def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        member_id=dict(type='str'),
        ca=dict(type='str', default='Fortinet_CA'),
        crl=dict(type='str', default=''),
        ocsp=dict(type='str', default=''),
        vdom=dict(type='str'),
    )

    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec, required_if=required_if)
    connection = Connection(module._socket_path)

    action = module.params['action']
    result = {}
    param_pass, param_err = param_check(module, connection)
    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
    elif action == 'add_object':
        code, response = add_cert_verify_object(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get_object':
        code, response = get_cert_verify_object(module, connection)
        result['res'] = response
        result['ok'] = True
    elif action == 'delete_object':
        code, data = get_cert_verify_object(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = delete_cert_verify_object(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
    elif action == 'add_member':
        code, data = get_cert_verify_object(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = add_cert_verify_object_member(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
    elif action == 'get_member':
        code, data = get_cert_verify_object(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = get_cert_verify_object_member(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
    elif action == 'delete_member':
        code, data = get_cert_verify_object(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = delete_cert_verify_object_member(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
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
