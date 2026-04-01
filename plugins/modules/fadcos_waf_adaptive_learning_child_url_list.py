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
module: fadcos_waf_adaptive_learning_child_url_list
short_description: Manage FortiADC Web Application Firewall adaptive learning child list url by RESTful API
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
    - name: Add WAF Adaptive Learning Child URL list entry
      fadcos_waf_adaptive_learning_child_url_list:
        action: add
        url: /home/test1
        name: al2

    - name: Add duplicate WAF Adaptive Learning Child URL list entry
      fadcos_waf_adaptive_learning_child_url_list:
        action: add
        url: /home/test1
        name: al2
        id: 1

    - name: Get WAF Adaptive Learning Child URL list entry
      fadcos_waf_adaptive_learning_child_url_list:
        action: get
        name: al2
        id: 2

    - name: edit WAF another Adaptive Learning Entry
      fadcos_waf_adaptive_learning_child_url_list:
        action: edit
        name: al2
        id: 2
        host_status: enable
        host: 3.3.3.4
        url: /home/test2

    - name: Get all WAF Adaptive Learning Child URL list
      fadcos_waf_adaptive_learning_child_url_list:
        action: get
        name: al2

    - name: delete WAF another Adaptive Learning Entry
      fadcos_waf_adaptive_learning_child_url_list:
        action: delete
        name: al2
        id: 5

    - name: edit non-existant WAF Adaptive Learning Entry
      fadcos_waf_adaptive_learning_child_url_list:
        action: edit
        name: al2
        id: 88
        host: 66.66.66.0
"""

RETURN = """
"""

before = {}
after = {}


def add_waf_adaptive_learning_child_url_list(module, connection):
    after['added'] = module.params
    id = module.params['id']
    pkey = module.params['name']
    host = module.params['host']
    host_status = module.params['host_status']
    url = module.params['url']
    payload = {
        'mkey': id,
        'host': host,
        'host_status': host_status,
        'url': url             
        }

    url = '/api/security_waf_adaptive_learning_child_url_list?pkey=' + pkey
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom

    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload)

    return code, response


def edit_waf_adaptive_learning_child_url_list(module, payload, connection):
    mkey = module.params['id']
    pkey = module.params['name']
    url = '/api/security_waf_adaptive_learning_child_url_list?pkey=' + pkey + '&mkey=' + mkey
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_waf_adaptive_learning_child_url_list(module, connection):
    mkey = module.params['id']
    pkey = module.params['name']
    payload = {}
    url = '/api/security_waf_adaptive_learning_child_url_list?pkey=' + pkey
    if mkey:
        url += '&mkey=' + mkey

    if is_vdom_enable(connection) :
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_waf_adaptive_learning_child_url_list(module, connection):
    after['deleted'] = module.params
    mkey = module.params['id']
    pkey = module.params['name']
    payload = {}
    url = '/api/security_waf_adaptive_learning_child_url_list?pkey=' + pkey + '&mkey=' + mkey

    if is_vdom_enable(connection) :
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
        if param != 'name' and param != 'id' and module.params[param]:
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
        err_msg.append('The name of adaptive_learning need to set.')
        res = False
    if (action == 'edit' or action == 'delete') and not module.params['id']:
        err_msg.append('The ID of entry to modify need to set.')
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
        id=dict(type='str'),
        name=dict(type='str'),
        host=dict(type='str'),
        url=dict(type='str'),
        host_status=dict(type='str'),
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
    if action == 'add':
        code, data = get_waf_adaptive_learning_child_url_list(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            result['res'] = 'An entry with the same name already exists.'
            result['changed'] = False
        else: 
            code, response = add_waf_adaptive_learning_child_url_list(module, connection)
            result['res'] = response
            if code == 200:
                result['changed'] = True
    elif action == 'get':
        code, response = get_waf_adaptive_learning_child_url_list(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_waf_adaptive_learning_child_url_list(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = False
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_waf_adaptive_learning_child_url_list(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_waf_adaptive_learning_child_url_list(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            code, response = delete_waf_adaptive_learning_child_url_list(module, connection)
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
