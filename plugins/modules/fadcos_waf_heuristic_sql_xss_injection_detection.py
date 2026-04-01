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
short_description: Manage FortiADC Web Application Firewall SQL XSS injection detection by RESTful API
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
    - name: Add WAF sql_xss_injection_detection
      fadcos_waf_heuristic_sql_xss_injection_detection:
        action: add
        name: sqlt2
        body_sql_injection_detection: disable
        body_xss_detection: disable
        cookie_sql_injection_detection: disable
        cookie_xss_detection: disable
        refer_sql_injection_detection: disable
        xss_severity: low

    - name: Add WAF sql_xss_injection_detection
      fadcos_waf_heuristic_sql_xss_injection_detection:
        action: add
        name: sqlt1
        body_sql_injection_detection: enable
        body_xss_detection: disable
        cookie_sql_injection_detection: disable
        cookie_xss_detection: disable
        refer_sql_injection_detection: disable
        xss_severity: low

    - name: edit WAF sql_xss_injection_detection
      fadcos_waf_heuristic_sql_xss_injection_detection:
        action: edit
        name: sqlt2
        xss_severity: high
        cookie_xss_detection: enable

    - name: get WAF sql_xss_injection_detection
      fadcos_waf_heuristic_sql_xss_injection_detection:
        action: get
        name: sqlt2

    - name: delete WAF sql_xss_injection_detection
      fadcos_waf_heuristic_sql_xss_injection_detection:
        action: delete
        name: sqlt1

    - name: delete non-existant WAF sql_xss_injection_detection
      fadcos_waf_heuristic_sql_xss_injection_detection:
        action: delete
        name: sqlt112131
"""

RETURN = """
"""

before = {}
after = {}


def add_waf_http_protocol_constraint(module, connection):
    after['added'] = module.params
    payload = {
            'body_sql_injection_detection': module.params['body_sql_injection_detection'],
            'body_xss_detection': module.params['body_xss_detection'],
            'cookie_sql_injection_detection': module.params['cookie_sql_injection_detection'],
            'cookie_xss_detection': module.params['cookie_xss_detection'],
            'mkey': module.params['name'],
            'refer_sql_injection_detection': module.params['refer_sql_injection_detection'],
            'refer_xss_detection': module.params['refer_xss_detection'],
            'sql_exception_name': module.params['sql_exception_name'],
            'sql_injection_action': module.params['sql_injection_action'],
            'sql_injection_detection': module.params['sql_injection_detection'],
            'sql_injection_severity': module.params['sql_injection_severity'],
            'uri_sql_injection_detection': module.params['uri_sql_injection_detection'],
            'uri_xss_detection': module.params['uri_xss_detection'],
            'xss_action': module.params['xss_action'],
            'xss_detection': module.params['xss_detection'],
            'xss_exception_name': module.params['xss_exception_name'],
            'xss_severity': module.params['xss_severity'],       
        }
    url = '/api/security_waf_heuristic_sql_xss_injection_detection'
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
    url = '/api/security_waf_heuristic_sql_xss_injection_detection'
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
    url = '/api/security_waf_heuristic_sql_xss_injection_detection?mkey=' + name
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
    url = '/api/security_waf_heuristic_sql_xss_injection_detection?mkey=' + name

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
        body_sql_injection_detection=dict(type='str'),
        body_xss_detection=dict(type='str'),
        cookie_sql_injection_detection=dict(type='str'),
        cookie_xss_detection=dict(type='str'),
        refer_sql_injection_detection=dict(type='str'),
        refer_xss_detection=dict(type='str'),
        sql_exception_name=dict(type='str'),
        sql_injection_action=dict(type='str'),
        sql_injection_detection=dict(type='str'),
        sql_injection_severity=dict(type='str'),
        uri_sql_injection_detection=dict(type='str'),
        uri_xss_detection=dict(type='str'),
        xss_action=dict(type='str'),
        xss_detection=dict(type='str'),
        xss_exception_name=dict(type='str'),
        xss_severity=dict(type='str'),
        vdom=dict(type='str'),
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
