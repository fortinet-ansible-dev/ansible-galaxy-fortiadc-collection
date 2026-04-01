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
module: fadcos_waf_json_validation_detection
short_description: Manage FortiADC Web Application Firewall json validation detection by RESTful API
description:
  - Manage FortiADC Web Application Firewall profile by RESTful API
version_added: "2.8"
author: ""
options:
"""

EXAMPLES = """
- name:
  hosts: all
  vars:
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Add WAF json_validation_detection
      fadcos_waf_json_validation_detection:
        action: add
        name: jst1
        security_action: alert
        exception_id: n1
        json_format_checks: enable
        json_limit_checks: disable
        json_schema_checks: disable
        json_sql_injection_checks: disable
        json_xss_checks: enable
        limit_max_array_value: 256
        limit_max_depth: 16
        limit_max_object_member: 64
        limit_max_string: 64

    - name: Add WAF duplicate json_validation_detection 
      fadcos_waf_json_validation_detection:
        action: add
        name: jst1
        security_action: alert
        exception_id: n1
        json_format_checks: enable
        json_limit_checks: disable
        json_schema_checks: disable

    - name: edit WAF json_validation_detection
      fadcos_waf_json_validation_detection:
        action: edit
        name: jst1
        security_action: block
        exception_id: n1
        limit_max_array_value: 200
        limit_max_depth: 32
        limit_max_object_member: 48
        severity: high

    - name: get WAF json_validation_detection
      fadcos_waf_json_validation_detection:
        action: get
        name: jst1

    - name: delete WAF json_validation_detection
      fadcos_waf_json_validation_detection:
        action: delete
        name: JS1

    - name: delete non-existant WAF json_validation_detection
      fadcos_waf_json_validation_detection:
        action: delete
        name: JS1

"""

RETURN = """
"""

before = {}
after = {}


def add_waf_json_validation_detection(module, connection):
    after['added'] = module.params
    payload = {
        'mkey': module.params['name'],
        'action': module.params['security_action'],
        'exception_id': module.params['exception_id'],
        'json_format_checks': module.params['json_format_checks'],
        'json_limit_checks': module.params['json_limit_checks'],
        'json_meta_os_checks': module.params['json_meta_os_checks'],
        'json_schema_checks': module.params['json_schema_checks'],
        'json_schema_id': module.params['json_schema_id'],
        'json_sql_injection_checks': module.params['json_sql_injection_checks'],
        'json_xss_checks': module.params['json_xss_checks'],
        'limit_max_array_value': module.params['limit_max_array_value'],
        'limit_max_depth': module.params['limit_max_depth'],
        'limit_max_object_member': module.params['limit_max_object_member'],
        'limit_max_string': module.params['limit_max_string'],
        'severity': module.params['severity']
        }
    url = '/api/security_waf_json_validation_detection'
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom

    if module.check_mode:
        code = 200
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload)

    return code, response


def get_waf_json_validation_detection(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_json_validation_detection'
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
            d_param = param
            if param == 'security_action':
                d_param = 'action'
            if d_param in data:
                before[d_param] = data[d_param]
            data[d_param] = module.params[param]
            after[d_param] = data[d_param]
            res = True
    return res, data

def edit_waf_json_validation_detection(module, payload, connection):
    name = module.params['name']
    url = '/api/security_waf_json_validation_detection?mkey=' + name
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


def delete_waf_json_validation_detection(module, connection):
    after['deleted'] = module.params
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_json_validation_detection?mkey=' + name

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
        exception_id=dict(type='str'),
        json_format_checks=dict(type='str'),
        json_limit_checks=dict(type='str'),
        json_meta_os_checks=dict(type='str'),
        json_schema_checks=dict(type='str'),
        json_schema_id=dict(type='str'),
        json_sql_injection_checks=dict(type='str'),
        json_xss_checks=dict(type='str'),
        limit_max_array_value=dict(type='str'),
        limit_max_depth=dict(type='str'),
        limit_max_object_member=dict(type='str'),
        limit_max_string=dict(type='str'),
        security_action=dict(type='str'),
        severity=dict(type='str'),
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
    code, data = get_waf_json_validation_detection(module, connection)
    if action == 'add':
        code, response = add_waf_json_validation_detection(module, connection)
        result['res'] = response
        if code == 200:
            result['changed'] = True
    elif action == 'get':
        code, response = get_waf_json_validation_detection(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_waf_json_validation_detection(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = False
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_waf_json_validation_detection(module, new_data, connection)
            result['res'] = response
            if code == 200:
                result['changed'] = True
    elif action == 'delete':
        code, data = get_waf_json_validation_detection(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            code, response = delete_waf_json_validation_detection(module, connection)
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
