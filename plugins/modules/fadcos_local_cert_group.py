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
module: fadcos_local_cert_group
description:
    Configure Local certificate group on FortiADC devices via RESTful APIs
version_added: "v1.0.0"
author: asri@fortinet.com
options:
    action:
        description: Type of action to perform on the object
        required: Yes
        type: String
        default: N/A
    name:
        description: Local certificate group name.
        required: Yes
        type: String
        default: N/A
    member_id:
        description: Local certificate group member ID.
        required: Yes
        type: String
        default: 
    OCSP_stapling:
        description: Select an OCSP Stapling configuration. The local certificate in the OCSP Stapling configuration must match the local certificate in the local certificate group member.
        required: No
        type: String
        default: 
    default:
        description: Enable if you want to make this local certificate the default for the group.
        required: No
        type: String
        default: disable
    extra_local_cert:
        description: FortiADC supports dual SSL certificates, one for an RSA-based SSL certificate and the other for an ECDSA-based SSL certificate. This option allows you to add an additional local certificate along with an additional OCSP stapling and intermediate CA group to a local certificate group configuration.
        required: No
        type: String
        default: 
    intermediate_cag:
        description: Select an intermediate CA group to add to the local group.
        required: No
        type: String
        default: 
    local_cert:
        description: Select a local certificate to add to the group.
        required: No
        type: String
        default: Factory
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
    - name: Manage Local Certificate Group
      fadcos_local_cert_group:
      action: add_group
      name: test_local_cert_group
    - name: Manage Local Certificate Group Members
      fadcos_local_cert_group:
        action: add_member
        name: test_local_cert_group
        local_cert: Fortiadc_ssl
"""

RETURN = """
fadcos_local_cert_group:
  description: The FortiADC local certificate group object created or updated.
  returned: always
  type: string
"""

def add_local_cert_group(module, connection):

    payload = {'mkey': module.params['name']}

    url = '/api/system_certificate_local_cert_group'
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom

    code, response = connection.send_request(url, payload)
    return code, response

def add_local_cert_group_member(module, connection):
    name = module.params['name']

    payload = {
        'OCSP_stapling': module.params['OCSP_stapling'],
        'default': module.params['default'],
        'extra_local_cert': module.params['extra_local_cert'],
        'intermediate_cag': module.params['intermediate_cag'],
        'local_cert': module.params['local_cert'],
        }

    url = '/api/system_certificate_local_cert_group_child_group_member?pkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload)
    return code, response

def get_local_cert_group(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/system_certificate_local_cert_group'

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

def get_local_cert_group_member(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/system_certificate_local_cert_group_child_group_member?pkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'GET')
    return code, response

def delete_local_cert_group(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/system_certificate_local_cert_group?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')
    return code, response

def delete_local_cert_group_member(module, connection):
    name = module.params['name']
    member_id = module.params['member_id']
    payload = {}
    url = '/api/system_certificate_local_cert_group_child_group_member?pkey=' + name + '&mkey=' + member_id

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')
    return code, response

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add_group' or action == 'delete_group' or action == 'add_member' or action == 'get_member' or action == 'delete_member') and not module.params['name']:
        err_msg.append('The local cert group name is required.')
        res = False
    if (action == 'delete_member') and not module.params['member_id']:
        err_msg.append('The local cert group member ID is required.')
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
        OCSP_stapling=dict(type='str', default=''),
        default=dict(type='str', default='disable'),
        extra_local_cert=dict(type='str', default=''),
        intermediate_cag=dict(type='str', default=''),
        local_cert=dict(type='str', default='Factory'),
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
    elif action == 'add_group':
        code, response = add_local_cert_group(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get_group':
        code, response = get_local_cert_group(module, connection)
        result['res'] = response
        result['ok'] = True
    elif action == 'delete_group':
        code, data = get_local_cert_group(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = delete_local_cert_group(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
    elif action == 'add_member':
        code, data = get_local_cert_group(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = add_local_cert_group_member(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
    elif action == 'get_member':
        code, data = get_local_cert_group(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = get_local_cert_group_member(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
    elif action == 'delete_member':
        code, data = get_local_cert_group(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = delete_local_cert_group_member(module, connection)
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
        and type(result['res']['payload']) is int and (result['res']['payload'] < 0 and result['res']['payload'] != -154) :
            result['err_msg'] = get_err_msg(connection, result['res']['payload'])
            result['changed'] = False
            result['failed'] = True
    module.exit_json(**result)

if __name__ == '__main__':
    main()
