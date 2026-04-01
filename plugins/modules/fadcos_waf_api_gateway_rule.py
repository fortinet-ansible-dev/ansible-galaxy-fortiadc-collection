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
module: fadcos_waf_api_gateway_rule
short_description: Manage FortiADC Web Application Firewall API gateway rules by RESTful API
description:
  - Manage FortiADC Web Application Firewall profile by RESTful API
version_added: "2.8"
author: ""
options:
"""

EXAMPLES = """
    - name: Add waf_api_gateway_rule
      fadcos_waf_api_gateway_rule:
        action: add
        name: test_rule1
        security_action: alert
        host: host1
        host_status: enable
        location: http-parameter
        method: GET POST HEAD OPTIONS TRACE CONNECT DELETE PUT PATCH OTHER
        parameter_name: acc
        rlimit_period: 60
        rlimit_reqs: 600
        rlimit_status: enable
        severity: low
        url_pattern: /home/test
        verification: enable

    - name: edit waf_api_gateway_rule
      fadcos_waf_api_gateway_rule:
        action: edit
        name: test_rule1
        parameter_name: add
        severity: high
        url_pattern: /home/qqq

    - name: Add waf_api_gateway_rule
      fadcos_waf_api_gateway_rule:
        action: add
        name: test_rule1
        security_action: alert

    - name: get waf_api_gateway_rule
      fadcos_waf_api_gateway_rule:
        action: get
        name: test_rule1

    - name: delete waf_api_gateway_rule
      fadcos_waf_api_gateway_rule:
        action: delete
        name: agr1
"""

RETURN = """
"""

before = {}
after = {}


def add_waf_api_gateway_rule(module, connection):
    after['added'] = module.params
    payload = {
        'mkey': module.params['name'], 
        'exception': module.params['exception'],
        'host': module.params['host'],
        'host_status': module.params['host_status'],
        'location': module.params['location'],
        'method': module.params['method'],
        'action': module.params['security_action'],
        'parameter_name': module.params['parameter_name'],
        'field_name': module.params['field_name'],
        'rlimit_period': module.params['rlimit_period'],
        'rlimit_reqs': module.params['rlimit_reqs'],
        'rlimit_status': module.params['rlimit_status'],
        'severity': module.params['severity'],
        'url_pattern': module.params['url_pattern'],
        'verification': module.params['verification'],
    }

    url = '/api/security_waf_api_gateway_rule'
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom

    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload)
    return code, response


def edit_waf_api_gateway_rule(module, payload, connection):
    name = module.params['name']
    url = '/api/security_waf_api_gateway_rule?mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'PUT')
    return code, response


def get_waf_api_gateway_rule(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_api_gateway_rule'
    if name:
        url += '?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_waf_api_gateway_rule(module, connection):
    after['deleted'] = module.params
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_api_gateway_rule?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False
    for param in module.params: 
        if param != 'name' and module.params[param]:
            d_param = param
            if param == 'security_action':
                d_param = 'action'
            if d_param in data:
                before[param] = data[d_param]
            data[param] = module.params[param] 
            after[param] = data[d_param]
            res = True
    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'delete') and not module.params['name']:
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
        exception=dict(type='str'),
        host=dict(type='str'),
        host_status=dict(type='str'),
        location=dict(type='str'),
        method=dict(type='str'),
        security_action=dict(type='str'),
        parameter_name=dict(type='str'),
        field_name=dict(type='str'),
        rlimit_period=dict(type='str'),
        rlimit_reqs=dict(type='str'),
        rlimit_status=dict(type='str'),
        severity=dict(type='str'),
        url_pattern=dict(type='str'),
        verification=dict(type='str'),
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
    code, data = get_waf_api_gateway_rule(module, connection)
    if action == 'add':
        code, response = add_waf_api_gateway_rule(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        result['res'] = data
    elif action == 'edit':
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = False
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_waf_api_gateway_rule(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            code, response = delete_waf_api_gateway_rule(module, connection)
            result['res'] = response
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
        if result['res']['payload'] == -15:
            result['failed'] = False

    if 'changed' in result.keys() and result['changed'] == True:
        result['diff'] = {
            'before': before,
            'after': after
        }
    else:
        if module.check_mode:
           result['res'] = 'Check mode: no changes detected.'  

    module.exit_json(**result)


if __name__ == '__main__':
    main()
