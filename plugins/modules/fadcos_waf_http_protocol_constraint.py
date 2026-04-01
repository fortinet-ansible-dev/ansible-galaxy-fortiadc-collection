#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_vdom_enable
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_to_str
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_need_update
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_global_admin
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fadcos_waf_http_protocol_constraint
short_description: Manage FortiADC Web Application Firewall http protocol constraint by RESTful API
description:
  - Manage FortiADC Web Application Firewall profile by RESTful API
version_added: "2.8"
author: ""
options:
"""

EXAMPLES = """
---
- name:
  hosts: all
  vars:
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Add WAF http_protocol_constraint
      fadcos_waf_http_protocol_constraint:
        action: add
        name: htest1
        constraint_method_override: disable
        illegal_host_name: disable
        illegal_host_name_action: alert
        illegal_host_name_severity: low
        illegal_http_version: disable
        illegal_http_version_action: alert
        illegal_http_version_severity: low
        illegal_multipart: disable
        illegal_multipart_action: alert
        illegal_multipart_severity: low
        max_body_length: 67108864
        max_body_length_action: alert
        max_body_length_severity: low
        max_cookie_number: 16
        max_cookie_number_action: alert
        max_cookie_number_severity: low
        max_header_length: 8192
        max_header_length_action: alert
        max_header_length_severity: low
        max_header_number: 50
        max_header_number_action: alert
        max_header_number_severity: low
        max_req_hdr_name_len: 1024
        max_req_hdr_name_len_action: alert
        max_req_hdr_name_len_severity: low
        max_req_hdr_value_len: 4096
        max_req_hdr_value_len_action: alert
        max_req_hdr_value_len_severity: low
        max_uri_length: 2048
        max_uri_length_action: deny
        max_uri_length_severity: low
        max_url_param_name_len: 1024
        max_url_param_name_len_action: alert
        max_url_param_name_len_severity: low
        max_url_param_value_len: 4096
        max_url_param_value_len_action: alert
        max_url_param_value_len_severity: low

    - name: get WAF http_protocol_constraint
      fadcos_waf_http_protocol_constraint:
        action: get
        name: htest1

    - name: edit WAF http_protocol_constraint
      fadcos_waf_http_protocol_constraint:
        action: edit
        name: htest1
        max_header_number: 88

    - name: delete WAF http_protocol_constraint
      fadcos_waf_http_protocol_constraint:
        action: delete
        name: HPC1
"""

RETURN = """
"""

before = {}
after = {}


def add_waf_http_protocol_constraint(module, connection):
    after['added'] = module.params
    payload = {
        'constraint_method_override': module.params['constraint_method_override'],
        'illegal_host_name': module.params['illegal_host_name'],
        'illegal_host_name_action': module.params['illegal_host_name_action'],
        'illegal_host_name_severity': module.params['illegal_host_name_severity'],
        'illegal_http_version': module.params['illegal_http_version'],
        'illegal_http_version_action': module.params['illegal_http_version_action'],
        'illegal_http_version_severity': module.params['illegal_http_version_severity'],
        'illegal_multipart': module.params['illegal_multipart'],
        'illegal_multipart_action': module.params['illegal_multipart_action'],
        'illegal_multipart_severity': module.params['illegal_multipart_severity'],
        'max_body_length': module.params['max_body_length'],
        'max_body_length_action': module.params['max_body_length_action'],
        'max_body_length_severity': module.params['max_body_length_severity'],
        'max_cookie_number': module.params['max_cookie_number'],
        'max_cookie_number_action': module.params['max_cookie_number_action'],
        'max_cookie_number_severity': module.params['max_cookie_number_severity'],
        'max_header_length': module.params['max_header_length'],
        'max_header_length_action': module.params['max_header_length_action'],
        'max_header_length_severity': module.params['max_header_length_severity'],
        'max_header_number': module.params['max_header_number'],
        'max_header_number_action': module.params['max_header_number_action'],
        'max_header_number_severity': module.params['max_header_number_severity'],
        'max_req_hdr_name_len': module.params['max_req_hdr_name_len'],
        'max_req_hdr_name_len_action': module.params['max_req_hdr_name_len_action'],
        'max_req_hdr_name_len_severity': module.params['max_req_hdr_name_len_severity'],
        'max_req_hdr_value_len': module.params['max_req_hdr_value_len'],
        'max_req_hdr_value_len_action': module.params['max_req_hdr_value_len_action'],
        'max_req_hdr_value_len_severity': module.params['max_req_hdr_value_len_severity'],
        'max_uri_length': module.params['max_uri_length'],
        'max_uri_length_action': module.params['max_uri_length_action'],
        'max_uri_length_severity': module.params['max_uri_length_severity'],
        'max_url_param_name_len': module.params['max_url_param_name_len'],
        'max_url_param_name_len_action': module.params['max_url_param_name_len_action'],
        'max_url_param_name_len_severity': module.params['max_url_param_name_len_severity'],
        'max_url_param_value_len': module.params['max_url_param_value_len'],
        'max_url_param_value_len_action': module.params['max_url_param_value_len_action'],
        'max_url_param_value_len_severity': module.params['max_url_param_value_len_severity'],
        'mkey': module.params['name']          
        }
    url = '/api/security_waf_http_protocol_constraint'
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom

    if module.check_mode:
        code = 200
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload)

    return code, response


def get_waf_http_protocol_constraint(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_http_protocol_constraint'
    if name:
        url += '?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response

def needs_update(module, data):
    res = False
    for param in module.params: 
        if param != 'name' and module.params[param]:
            if param in data:
                before[param] = data[param]
            data[param] = module.params[param]
            after[param] = data[param]
            res = True
    return res, data

def edit_waf_http_protocol_constraint(module, payload, connection):
    name = module.params['name']
    url = '/api/security_waf_http_protocol_constraint?mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    if module.check_mode:
        code = 200
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'PUT')
    # response["log"] = payload
    # response["url"] = url
    return code, response


def delete_waf_http_protocol_constraint(module, connection):
    after['deleted'] = module.params
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_http_protocol_constraint?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    if module.check_mode:
        code = 200
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'DELETE')
    return code, response


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'delete'  or action == 'edit') and not module.params['name']:
        err_msg.append('The name need to set.')
        res = False
    if is_vdom_enable(connection) and not module.params['vdom']:
        err_msg.append(
            'The vdom is enable in system setting, vdom must be set.')
        res = False
    elif is_vdom_enable(connection) and module.params['vdom'] and not is_user_in_vdom(connection, module.params['vdom']):
        err_msg.append('The user can not accsee the vdom ' +
                       module.params['vdom'])
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        vdom=dict(type='str'),
        constraint_method_override=dict(type='str'),
        illegal_host_name=dict(type='str'),
        illegal_host_name_action=dict(type='str'),
        illegal_host_name_severity=dict(type='str'),
        illegal_http_version=dict(type='str'),
        illegal_http_version_action=dict(type='str'),
        illegal_http_version_severity=dict(type='str'),
        illegal_multipart=dict(type='str'),
        illegal_multipart_action=dict(type='str'),
        illegal_multipart_severity=dict(type='str'),
        max_body_length=dict(type='str'),
        max_body_length_action=dict(type='str'),
        max_body_length_severity=dict(type='str'),
        max_cookie_number=dict(type='str'),
        max_cookie_number_action=dict(type='str'),
        max_cookie_number_severity=dict(type='str'),
        max_header_length=dict(type='str'),
        max_header_length_action=dict(type='str'),
        max_header_length_severity=dict(type='str'),
        max_header_number=dict(type='str'),
        max_header_number_action=dict(type='str'),
        max_header_number_severity=dict(type='str'),
        max_req_hdr_name_len=dict(type='str'),
        max_req_hdr_name_len_action=dict(type='str'),
        max_req_hdr_name_len_severity=dict(type='str'),
        max_req_hdr_value_len=dict(type='str'),
        max_req_hdr_value_len_action=dict(type='str'),
        max_req_hdr_value_len_severity=dict(type='str'),
        max_uri_length=dict(type='str'),
        max_uri_length_action=dict(type='str'),
        max_uri_length_severity=dict(type='str'),
        max_url_param_name_len=dict(type='str'),
        max_url_param_name_len_action=dict(type='str'),
        max_url_param_name_len_severity=dict(type='str'),
        max_url_param_value_len=dict(type='str'),
        max_url_param_value_len_action=dict(type='str'),
        max_url_param_value_len_severity=dict(type='str')
    )

    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True,
                           required_if=required_if)
    connection = Connection(module._socket_path)

    action = module.params['action']
    result = {}
    param_pass, param_err = param_check(module, connection)
    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
        module.exit_json(**result)
    code, data = get_waf_http_protocol_constraint(module, connection)
    if action == 'add':
        code, response = add_waf_http_protocol_constraint(module, connection)
        result['res'] = response
        if code == 200:
            result['changed'] = True
    elif action == 'get':
        code, response = get_waf_http_protocol_constraint(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_waf_http_protocol_constraint(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = False
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_waf_http_protocol_constraint(module, new_data, connection)
            result['res'] = response
            if code == 200:
                result['changed'] = True
    elif action == 'delete':
        code, data = get_waf_http_protocol_constraint(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            code, response = delete_waf_http_protocol_constraint(module, connection)
            result['res'] = response
            if code == 200:
                result['changed'] = True
        else:
            result['failed'] = False
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    if 'res' in result.keys() and type(result['res']) is dict\
            and type(result['res']['payload']) is int and result['res']['payload'] < 0:
        result['err_msg'] = get_err_msg(connection, result['res']['payload'])
        result['changed'] = False
        result['failed'] = True
        if result['res']['payload'] == -15 or result['res']['payload'] == -13:
            result['failed'] = False

    if 'changed' in result.keys() and result['changed'] == True:
        result['diff'] = {
            'before': before,
            'after': after
        }

    module.exit_json(**result)


if __name__ == '__main__':
    main()
