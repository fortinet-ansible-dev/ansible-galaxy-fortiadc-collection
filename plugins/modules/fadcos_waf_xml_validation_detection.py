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
module: fadcos_waf_xml_validation_detection
short_description: Manage FortiADC Web Application Firewall xml validation detection by RESTful API
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
    - name: Add WAF xml_validation_detection
      fadcos_waf_xml_validation_detection:
        action: add
        name: xxx2
        limit_max_attr: 256
        limit_max_attr_name_len: 128
        limit_max_attr_value_len: 128
        limit_max_cdata_len: 65535
        limit_max_elem_child: 65535
        limit_max_elem_depth: 256
        limit_max_elem_name_len: 128
        limit_max_namespace: 16
        limit_max_namespace_uri_len: 256
        severity: low
        soap_format_checks: enable
        soap_wsdl_checks: enable
        xml_format_checks: enable
        xml_limit_checks: enable
        xml_schema_checks: enable

    - name: edit WAF xml_validation_detection
      fadcos_waf_xml_validation_detection:
        action: edit
        name: xxx2
        limit_max_attr: 200
        limit_max_attr_name_len: 200  
        limit_max_attr_value_len: 200
        security_action: block

    - name: get WAF xml_validation_detection
      fadcos_waf_xml_validation_detection:
        action: get
        name: xxx2

    - name: delete WAF xml_validation_detection
      fadcos_waf_xml_validation_detection:
        action: delete
        name: xxx1
"""

RETURN = """
"""

before = {}
after = {}


def add_waf_xml_validation_detection(module, connection):
    after['added'] = module.params
    payload = {
        'mkey': module.params['name'],
        'action': module.params['security_action'],
        'exception_id': module.params['exception_id'],
        'limit_max_attr': module.params['limit_max_attr'],
        'limit_max_attr_name_len': module.params['limit_max_attr_name_len'],
        'limit_max_attr_value_len': module.params['limit_max_attr_value_len'],
        'limit_max_cdata_len': module.params['limit_max_cdata_len'],
        'limit_max_elem_child': module.params['limit_max_elem_child'],
        'limit_max_elem_depth': module.params['limit_max_elem_depth'],
        'limit_max_elem_name_len': module.params['limit_max_elem_name_len'],
        'limit_max_namespace': module.params['limit_max_namespace'],
        'limit_max_namespace_uri_len': module.params['limit_max_namespace_uri_len'],
        'severity': module.params['severity'],
        'soap_format_checks': module.params['soap_format_checks'],
        'soap_wsdl_checks': module.params['soap_wsdl_checks'],
        'soap_wsdl_id': module.params['soap_wsdl_id'],
        'xml_format_checks': module.params['xml_format_checks'],
        'xml_limit_checks': module.params['xml_limit_checks'],
        'xml_schema_checks': module.params['xml_schema_checks'],
        'xml_schema_id': module.params['xml_schema_id'],
        'xml_sql_injection_checks': module.params['xml_sql_injection_checks'],
        'xml_xss_checks': module.params['xml_xss_checks'],
    }
    url = '/api/security_waf_xml_validation_detection'
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom

    if module.check_mode:
        code = 200
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload)

    return code, response


def get_waf_xml_validation_detection(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_xml_validation_detection'
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

def edit_waf_xml_validation_detection(module, payload, connection):
    name = module.params['name']
    url = '/api/security_waf_xml_validation_detection?mkey=' + name
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


def delete_waf_xml_validation_detection(module, connection):
    after['deleted'] = module.params
    name = module.params['name']
    payload = {}
    url = '/api/security_waf_xml_validation_detection?mkey=' + name

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
        security_action=dict(type='str'),
        exception_id=dict(type='str'),
        limit_max_attr=dict(type='str'),
        limit_max_attr_name_len=dict(type='str'),
        limit_max_attr_value_len=dict(type='str'),
        limit_max_cdata_len=dict(type='str'),
        limit_max_elem_child=dict(type='str'),
        limit_max_elem_depth=dict(type='str'),
        limit_max_elem_name_len=dict(type='str'),
        limit_max_namespace=dict(type='str'),
        limit_max_namespace_uri_len=dict(type='str'),
        severity=dict(type='str'),
        soap_format_checks=dict(type='str'),
        soap_wsdl_checks=dict(type='str'),
        soap_wsdl_id=dict(type='str'),
        xml_format_checks=dict(type='str'),
        xml_limit_checks=dict(type='str'),
        xml_schema_checks=dict(type='str'),
        xml_schema_id=dict(type='str'),
        xml_sql_injection_checks=dict(type='str'),
        xml_xss_checks=dict(type='str'),
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
    code, data = get_waf_xml_validation_detection(module, connection)
    if action == 'add':
        code, response = add_waf_xml_validation_detection(module, connection)
        result['res'] = response
        if code == 200:
            result['changed'] = True
    elif action == 'get':
        code, response = get_waf_xml_validation_detection(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_waf_xml_validation_detection(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            result['failed'] = False
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_waf_xml_validation_detection(module, new_data, connection)
            result['res'] = response
            if code == 200:
                result['changed'] = True
    elif action == 'delete':
        code, data = get_waf_xml_validation_detection(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            code, response = delete_waf_xml_validation_detection(module, connection)
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
