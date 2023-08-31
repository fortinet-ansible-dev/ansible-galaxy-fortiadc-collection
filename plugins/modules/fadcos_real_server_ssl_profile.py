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
module: fadcos_real_server_ssl_profile
description:
    Configure Real Server SSL Profile on FortiADC devices via RESTful APIs
version_added: "v1.0.0"
author: asri@fortinet.com
options:
    action:
        description: Type of action to perform on the object
        required: Yes
        type: String
        default: N/A
    name:
        description: Real server SSL profile object name.
        required: Yes
        type: String
        default: N/A
    allow_ssl_versions:
        description: Allowed SSL version.
        required: No
        type: String
        default: sslv3 tlsv1.0 tlsv1.1 tlsv1.2
    ciphers_tlsv13:
        description: TLSv1.3 ciphers.
        required: No
        type: List
        default: 
    customized_ssl_ciphers_flag:
        description: Enable/disable use of user-specified cipher suites. When enabled, you must select a Customized SSL Cipher.
        required: No
        type: String
        default: disable
    new_ssl_ciphers_long:
        description: If the customize cipher flag is enabled, specify a colon-separated, ordered list of cipher suites. An empty string is allowed. If empty, the default cipher suite list is used.
        required: No
        type: List
        default: 
    renegotiate_period:
        description: Specify the interval from the initial connect time that FortiADC renegotiates an SSL session. The unit of measurement can be second (default), minute, or hour, e.g., 100s, 20m, or 1h.
        required: No
        type: String
        default: 0
    renegotiate_size:
        description: Specify the amount (in MB) of application data that must have been transmitted over the secure connection before FortiADC initiates the renegotiation of an SSL session.
        required: No
        type: String
        default: 0
    renegotiation:
        description: This option controls how FortiADC responds to mid-stream SSL reconnection requests either initiated by real servers or forced by FortiADC.
        required: No
        type: String
        default: enable
    renegotiation_deny_action:
        description: This option becomes available when Renegotiation is disabled on the server side. In that case, you must select an action that FortiADC will take when denying an SSL renegotiation request: ignore or terminate.
        required: No
        type: String
        default: ignore
    secure_renegotiation:
        description: Secure renegotiation of SSL connections. (request/require/require_strict)
        required: No
        type: String
        default: require
    server_OCSP_stapling:
        description: Enable/disable server side OCSP stapling.
        required: No
        type: String
        default: disable
    session_reuse_flag:
        description: Enable/disable SSL session reuse.
        required: No
        type: String
        default: disable
    session_reuse_limit:
        description: Session reuse limit, the default is 0 (disabled). The valid range is 0-1048576.
        required: No
        type: String
        default: 0
    sni_forward_flag:
        description: Enable/disable forwarding the client SNI value to the server. The SNI value will be forwarded to the real server only when the client-side ClientHello message contains a valid SNI value; otherwise, nothing is forwarded.
        required: No
        type: String
        default: disable
    ssl:
        description: Enable/disable SSL for the connection between the FortiADC and the real server.
        required: No
        type: String
        default: disable
    tls_ticket_flag:
        description: Enable/disable TLS ticket-based session reuse.
        required: No
        type: String
        default: disable
    local_cert:
        description: Select a local certificate.
        required: No
        type: String
        default: Factory
    cert_verify:
        description: Specify a Certificate Verify configuration object to validate server certificates. This Certificate Verify object must include a CA group and may include OCSP and CRL checks.
        required: No
        type: String
        default: 
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
    - name: Manage Real Server SSL Profile
      fadcos_real_server_ssl_profile:
        action: add
        ssl: enable
        name: test_server_ssl_profile
        vdom: root
"""

RETURN = """
fadcos_real_server_ssl_profile:
  description: The FortiADC real server ssl profile object created or updated.
  returned: always
  type: string
"""

def add_real_server_ssl_profile(module, connection):
    
    payload = {
            'mkey': module.params['name'],
            'allow_ssl_versions': module.params['allow_ssl_versions'],
            'ciphers_tlsv13': list_to_str(module.params['ciphers_tlsv13']),
            'customized_ssl_ciphers_flag': module.params['customized_ssl_ciphers_flag'],
            'new_ssl_ciphers_long': list_to_str(module.params['new_ssl_ciphers_long']),
            'renegotiate_period': module.params['renegotiate_period'],
            'renegotiate_size': module.params['renegotiate_size'],
            'renegotiation': module.params['renegotiation'],
            'renegotiation_deny_action': module.params['renegotiation_deny_action'],
            'secure_renegotiation': module.params['secure_renegotiation'],
            'server_OCSP_stapling': module.params['server_OCSP_stapling'],
            'session_reuse_flag': module.params['session_reuse_flag'],
            'session_reuse_limit': module.params['session_reuse_limit'],
            'sni_forward_flag': module.params['sni_forward_flag'],
            'ssl': module.params['ssl'],
            'tls_ticket_flag': module.params['tls_ticket_flag'],
            'local_cert': module.params['local_cert'],
            'cert_verify': module.params['cert_verify'],
        }

    url = '/api/load_balance_real_server_ssl_profile'
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom
    
    code, response = connection.send_request(url, payload)

    return code, response

def get_real_server_ssl_profile(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/load_balance_real_server_ssl_profile'

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

def delete_real_server_ssl_profile(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/load_balance_real_server_ssl_profile?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')
    return code, response

def edit_real_server_ssl_profile(module, payload, connection):
    name = module.params['name']
    url = '/api/load_balance_real_server_ssl_profile?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'PUT')
    return code, response

def update_real_server_ssl_profile(module, data):
    res = False

    for key in module.params:
        if key in data:
            if key == 'ciphers_tlsv13' or key == 'new_ssl_ciphers_long':
                if list_need_update(module.params[key], data[key]):
                    data[key] = list_to_str(module.params[key])
                    res = True
            elif module.params[key] != data[key]:
                data[key] = module.params[key]
                res = True

    return res, data

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'edit' or action == 'delete') and not module.params['name']:
        err_msg.append('The client SSL profile name is required.')
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
        allow_ssl_versions=dict(type='str', default='sslv3 tlsv1.0 tlsv1.1 tlsv1.2'),
        ciphers_tlsv13=dict(type='list'),
        customized_ssl_ciphers_flag=dict(type='str', default='disable'),
        new_ssl_ciphers_long=dict(type='list'),
        renegotiate_period=dict(type='str', default='0'),
        renegotiate_size=dict(type='str', default='0'),
        renegotiation=dict(type='str', default='enable'),
        renegotiation_deny_action=dict(type='str', default='ignore'),
        secure_renegotiation=dict(type='str', default='require'),
        server_OCSP_stapling=dict(type='str', default='disable'),
        session_reuse_flag=dict(type='str', default='disable'),
        session_reuse_limit=dict(type='str', default='0'),
        sni_forward_flag=dict(type='str', default='disable'),
        ssl=dict(type='str', default='disable'),
        tls_ticket_flag=dict(type='str', default='disable'),
        local_cert=dict(type='str', default='Factory'),
        cert_verify=dict(type='str', default=''),
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
    elif action == 'add':
        code, response = add_real_server_ssl_profile(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_real_server_ssl_profile(module, connection)
        result['res'] = response
        result['ok'] = True
    elif action == 'edit':
        code, data = get_real_server_ssl_profile(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = update_real_server_ssl_profile(module, data['payload'])
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            code, response = edit_real_server_ssl_profile(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_real_server_ssl_profile(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = delete_real_server_ssl_profile(module, connection)
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
        and type(result['res']['payload']) is int and result['res']['payload'] < 0:
            result['err_msg'] = get_err_msg(connection, result['res']['payload'])
            result['changed'] = False
            result['failed'] = True
    module.exit_json(**result)

if __name__ == '__main__':
    main()
