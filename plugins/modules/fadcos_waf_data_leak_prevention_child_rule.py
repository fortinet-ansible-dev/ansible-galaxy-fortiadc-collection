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
module: fadcos_waf_data_leak_prevention
short_description: Manage FortiADC Web Application Firewall adaptive learning by RESTful API
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
    - name: Add WAF data_leak_prevention_child_rule
      fadcos_waf_data_leak_prevention_child_rule:
        action: add
        name: dl1
        threshold: 555
        type: sdt
        uri: /home/user
        sensitive_data_type: Email

    - name: Add another WAF data_leak_prevention_child_rule
      fadcos_waf_data_leak_prevention_child_rule:
        action: add
        name: dl1
        threshold: 777
        type: sensors
        uri: /abc123/aeet
        sensor: sensor1

    - name: get WAF data_leak_prevention_child_rule
      fadcos_waf_data_leak_prevention_child_rule:
        action: get
        name: dl1
        id: 1

    - name: edit WAF data_leak_prevention_child_rule
      fadcos_waf_data_leak_prevention_child_rule:
        action: edit
        name: dl1
        id: 1        
        threshold: 2345
        uri: /work/comp1

    - name: get all WAF data_leak_prevention_child_rule
      fadcos_waf_data_leak_prevention_child_rule:
        action: get
        name: dl1

    - name: delete WAF data_leak_prevention_child_rule
      fadcos_waf_data_leak_prevention_child_rule:
        action: delete
        name: dl1
        id: 2
"""

RETURN = """
"""

before = {}
after = {}


def add_waf_data_leak_prevention_child_rule(module, connection):
    after['added'] = module.params
    pkey = module.params['name']
    sensitive_data_type = module.params['sensitive_data_type']
    sensor = module.params['sensor']
    threshold = module.params['threshold']
    type = module.params['type']
    uri = module.params['uri']
    payload = {
        'sdt': sensitive_data_type,
        'sensor': sensor,
        'threshold': threshold,
        'type': type,
        'uri': uri               
        }

    url = '/api/security_waf_data_leak_prevention_child_rule?pkey=' + pkey
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom

    if module.check_mode:
        code = 200
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload)

    return code, response


def edit_waf_data_leak_prevention_child_rule(module, payload, connection):
    pkey = module.params['name']
    mkey = module.params['id']
    url = '/api/security_waf_data_leak_prevention_child_rule?pkey=' + pkey + '&mkey=' + mkey
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


def get_waf_data_leak_prevention_child_rule(module, connection):
    pkey = module.params['name']
    mkey = module.params['id']
    payload = {}
    url = '/api/security_waf_data_leak_prevention_child_rule?pkey=' + pkey
    if mkey:
        url += '&mkey=' + mkey

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_waf_data_leak_prevention_child_rule(module, connection):
    after['deleted'] = module.params
    pkey = module.params['name']
    mkey = module.params['id']
    payload = {}
    url = '/api/security_waf_data_leak_prevention_child_rule?pkey=' + pkey + '&mkey=' + mkey

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
            d_param = param
            if param == 'sensitive_data_type':
                d_param = 'sdt'
            if d_param in data:
                before[d_param] = data[d_param]
            data[d_param] = module.params[param]
            after[d_param] = data[d_param]
            res = True
    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'edit' or action == 'delete') and not module.params['name']:
        err_msg.append('The name of data leak prevention entry need to set.')
        res = False
    if (action == 'edit' or action == 'delete') and not module.params['id']:
        err_msg.append('The name of child rule ID of data leak prevention entry need to set.')
        res = False
    if (action == 'add' or action == 'edit'):
        if (module.params['type'] == 'sensors' and not module.params['sensor']):
            err_msg.append('The field of \'sensor\' needs to be set for a  \'sensors\' typed data.')
            res = False
        if (module.params['type'] == 'sdt' and not module.params['sensitive_data_type']):
            err_msg.append('The field of \'sensitive_data_type\' needs to be set for a \'sdt\' typed data.')
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
        id=dict(type='str'),
        type=dict(type='str'),
        threshold=dict(type='str'),
        sensor=dict(type='str'),
        sensitive_data_type=dict(type='str'),
        uri=dict(type='str')
        
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
    code, data = get_waf_data_leak_prevention_child_rule(module, connection)
    if action == 'add':
        code, response = add_waf_data_leak_prevention_child_rule(module, connection)
        result['res'] = response
        if code == 200:
            result['changed'] = True
    elif action == 'get':
        code, response = get_waf_data_leak_prevention_child_rule(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_waf_data_leak_prevention_child_rule(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = False
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_waf_data_leak_prevention_child_rule(module, new_data, connection)
            result['res'] = response
            if code == 200:
                result['changed'] = True
    elif action == 'delete':
        code, data = get_waf_data_leak_prevention_child_rule(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            code, response = delete_waf_data_leak_prevention_child_rule(module, connection)
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
