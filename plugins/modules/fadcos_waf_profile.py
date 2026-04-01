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
module: fadcos_waf_profile
short_description: Manage FortiADC Web Application Firewall profile by RESTful API
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
    - name: Add WAF Profile
      fadcos_waf_profile:
        action: add
        name: waf_tt1

    - name: Get WAF Profile
      fadcos_waf_profile:
        action: get
        name: waf_tt1

    - name: Edit WAF Profile
      fadcos_waf_profile:
        action: edit
        name: waf_tt1
        adaptive_learning: Medium_Learning
        cookie_security: CE1

    - name: Delete WAF Profile
      fadcos_waf_profile:
        action: delete
        name: waf_tt1
"""

RETURN = """
"""

before = {}
after = {}


def add_waf_profile(module, connection):
    after['added'] = module.params
    name = module.params['name']
    adaptive_learning = module.params['adaptive_learning']
    advanced_protection_name = module.params['advanced_protection_name']
    api_gateway_policy_name = module.params['api_gateway_policy_name']
    api_security = module.params['api_security']
    biometrics_based_detection = module.params['biometrics_based_detection']
    bot_detection_name = module.params['bot_detection_name']
    brute_force_login_name = module.params['brute_force_login_name']
    cookie_security = module.params['cookie_security']
    cors_protection = module.params['cors_protection']
    credential_stuffing_defense = module.params['credential_stuffing_defense']
    csrf_protection = module.params['csrf_protection']
    data_leak_prevention_name = module.params['data_leak_prevention_name']
    desc = module.params['desc']
    exception_name = module.params['exception_name']
    fingerprint_based_detection = module.params['fingerprint_based_detection']
    heuristic_sql_xss_injection_detection = module.params['heuristic_sql_xss_injection_detection']
    http_header_security_name = module.params['http_header_security_name']
    http_protocol_constraint = module.params['http_protocol_constraint']
    input_validation_policy_name = module.params['input_validation_policy_name']
    json_validation_name = module.params['json_validation_name']
    openapi_validation_name = module.params['openapi_validation_name']
    rule_match_record = module.params['rule_match_record']
    threshold_based_detection = module.params['threshold_based_detection']
    url_protection = module.params['url_protection']
    web_attack_signature = module.params['web_attack_signature']
    xml_validation_name = module.params['xml_validation_name']

    payload = {
        'mkey': name,
        'adaptive_learning': adaptive_learning,
        'advanced_protection_name': advanced_protection_name,
        'api_gateway_policy_name': api_gateway_policy_name,
        'api_security': api_security,
        'biometrics_based_detection': biometrics_based_detection,
        'bot_detection_name': bot_detection_name,
        'brute_force_login_name': brute_force_login_name,
        'cookie_security': cookie_security,
        'cors_protection': cors_protection,
        'credential_stuffing_defense': credential_stuffing_defense,
        'csrf_protection': csrf_protection,
        'data_leak_prevention_name': data_leak_prevention_name,
        'desc': desc,
        'exception_name': exception_name,
        'fingerprint_based_detection': fingerprint_based_detection,
        'heuristic_sql_xss_injection_detection': heuristic_sql_xss_injection_detection,
        'http_header_security_name': http_header_security_name,
        'http_protocol_constraint': http_protocol_constraint,
        'input_validation_policy_name': input_validation_policy_name,
        'json_validation_name': json_validation_name,
        'openapi_validation_name': openapi_validation_name,
        'rule_match_record': rule_match_record,
        'threshold_based_detection': threshold_based_detection,
        'url_protection': url_protection,
        'web_attack_signature': web_attack_signature,
        'xml_validation_name': xml_validation_name,
               }

    url = '/api/security_waf_profile'
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom

    if module.check_mode:
        code = 200
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload)

    return code, response


def edit_waf_profile(module, payload, connection):
    name = module.params['name']
    url = '/api/security_waf_profile?mkey=' + name
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


def get_waf_profile(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_profile'
    if name:
        url += '?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_waf_profile(module, connection):
    after['deleted'] = module.params
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_profile?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    if module.check_mode:
        code = 200
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False
    for param in module.params:
        if param in data:
            before[param] = data[param]
        data[param] = module.params[param]
        after[param] = data[param]
        res = True
    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'edit' or action == 'delete') and not module.params['name']:
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
        adaptive_learning=dict(type='str'),
        advanced_protection_name=dict(type='str'),
        api_gateway_policy_name=dict(type='str'),
        api_security=dict(type='str'),
        biometrics_based_detection=dict(type='str'),
        bot_detection_name=dict(type='str'),
        brute_force_login_name=dict(type='str'),
        cookie_security=dict(type='str'),
        cors_protection=dict(type='str'),
        credential_stuffing_defense=dict(type='str'),
        csrf_protection=dict(type='str'),
        data_leak_prevention_name=dict(type='str'),
        desc=dict(type='str'),
        exception_name=dict(type='str'),
        fingerprint_based_detection=dict(type='str'),
        heuristic_sql_xss_injection_detection=dict(type='str'),
        http_header_security_name=dict(type='str'),
        http_protocol_constraint=dict(type='str'),
        input_validation_policy_name=dict(type='str'),
        json_validation_name=dict(type='str'),
        openapi_validation_name=dict(type='str'),
        rule_match_record=dict(type='str', default='disable'),
        threshold_based_detection=dict(type='str'),
        url_protection=dict(type='str'),
        web_attack_signature=dict(type='str'),
        xml_validation_name=dict(type='str'),
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
    code, data = get_waf_profile(module, connection)
    if action == 'add':
        code, response = add_waf_profile(module, connection)
        result['res'] = response
        if code == 200:
            result['changed'] = True
    elif action == 'get':
        code, response = get_waf_profile(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_waf_profile(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = False
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_waf_profile(module, new_data, connection)
            result['res'] = response
            if code == 200:
                result['changed'] = True
    elif action == 'delete':
        code, data = get_waf_profile(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            code, response = delete_waf_profile(module, connection)
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
        if result['res']['payload'] == -15:
            result['failed'] = False

    if 'changed' in result.keys() and result['changed'] == True:
        result['diff'] = {
            'before': before,
            'after': after
        }

    module.exit_json(**result)


if __name__ == '__main__':
    main()
