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
module: fadcos_waf_cookie_security
short_description: Manage FortiADC Web Application Firewall cookie signature by RESTful API
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
    - name: Add cookie signature
      fadcos_waf_cookie_security:
        action: add
        name: watk1
    - name: get cookie signature
      fadcos_waf_cookie_security:
        action: get
        name: watk1
    - name: delete cookie signature
      fadcos_waf_cookie_security:
        action: delete
        name: watk1  
"""

RETURN = """
"""

before = {}
after = {}


def add_waf_cookie_security(module, connection):
    after['added'] = module.params
    name = module.params['name']
    allow_suspicious_cookies = module.params['allow_suspicious_cookies']
    cookie_replay = module.params['cookie_replay']
    dont_blk_until = module.params['dont_blk_until']
    enc_cookie_type = module.params['enc_cookie_type']
    security_action = module.params['security_action']
    exception = module.params['exception']
    http_only = module.params['http_only']
    max_age = module.params['max_age']
    rm_cookie = module.params['rm_cookie']
    samesite = module.params['samesite']
    sec_mode = module.params['sec_mode']
    secure = module.params['secure']
    severity = module.params['severity']
    payload = {
        'mkey': name, 
        'allow_suspicious_cookies': allow_suspicious_cookies,
        'action': security_action,
        'cookie_replay': cookie_replay,
        'dont_blk_until': dont_blk_until,
        'enc_cookie_type': enc_cookie_type,
        'exception': exception,
        'http_only': http_only,
        'max_age': max_age,
        'rm_cookie': rm_cookie,
        'samesite': samesite,
        'sec_mode': sec_mode,
        'secure': secure,
        'severity': severity
    }

    url = '/api/security_waf_cookie_security'
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom

    if module.check_mode:
        code = 200
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload)
    return code, response


def edit_waf_cookie_security(module, payload, connection):
    name = module.params['name']
    url = '/api/security_waf_cookie_security?mkey=' + name
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    if module.check_mode:
        code = 200
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'PUT')
    return code, response


def get_waf_cookie_security(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_cookie_security'
    if name:
        url += '?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_waf_cookie_security(module, connection):
    after['deleted'] = module.params
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_cookie_security?mkey=' + name

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
        if param != 'name' and module.params[param]:
            if param in data:
                before[param] = data[param]
            data[param] = module.params[param] 
            after[param] = data[param]
            res = True
    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    sec_mode = module.params['sec_mode']
    err_msg = []

    if (action == 'add' or action == 'edit' or action == 'delete') and not module.params['name']:
        err_msg.append('The name need to set.')
        res = False
    if sec_mode != 'no' and sec_mode != 'signed' and sec_mode != 'encrypted' :
        err_msg.append('The value of Security Mode (\'sec_mode\') can only be set to \'no\', \'encrypted\', or \'signed\' (case-sensitive).');
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
        allow_suspicious_cookies=dict(type='str', default='never'),
        cookie_replay=dict(type='str', default='disable'),
        security_action=dict(type='str'),
        enc_cookie_type=dict(type='str', default='all'),
        dont_blk_until=dict(type='str'),
        exception=dict(type='str'),
        http_only=dict(type='str', default='disable'),
        max_age=dict(type='str', default='0'),
        rm_cookie=dict(type='str', default='disable'),
        sec_mode=dict(type='str', default='no'),
        samesite=dict(type='str', default='nothing'),
        secure=dict(type='str', default='disable'),
        severity=dict(type='str', default='medium'),
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
    code, data = get_waf_cookie_security(module, connection)
    if action == 'add':
        code, response = add_waf_cookie_security(module, connection)
        result['res'] = response
        if code == 200:
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
            code, response = edit_waf_cookie_security(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            code, response = delete_waf_cookie_security(module, connection)
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

    module.exit_json(**result)


if __name__ == '__main__':
    main()
