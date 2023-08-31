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
module: fadcos_client_ssl_profile
description:
	Configure Client SSL Profile on FortiADC devices via RESTful APIs
version_added: "v1.0.0"
author: asri@fortinet.com
options:
    action:
        description: Type of action to perform on the object
        required: Yes
        type: String
        default: N/A
    name:
        description: Client SSL Profile name.
        required: Yes
        type: String
        default: N/A
    backend_ciphers_tlsv13:
        description: TLSv1.3 ciphers, only available if the backendTLSv1.3 is enabled.
        required: No
        type: String
        default: 
    backend_customized_ssl_ciphers_flag:
        description: Enabled by default. You must specify the backend customized SSL ciphers.
        required: No
        type: String
        default: enable
    backend_ssl_OCSP_stapling_support:
        description: Enable it to let FortiADC support OCSP stapling at the backend.
        required: No
        type: String
        default: disable
    backend_ssl_allowed_versions:
        description: Supported backend SSL versions.
        required: No
        type: String
        default: sslv3 tlsv1.0 tlsv1.1 tlsv1.2
    backend_ssl_ciphers:
        description: Backend SSL cipher suite.
        required: No
        type: List
        default: 
    backend_ssl_sni_forward:
        description: Enable it to let FortiADC forward Server Name Indication (SNI) from the client to the backend.
        required: No
        type: String
        default: disable
    client_certificate_verify:
        description: The client certificate verify configuration object.
        required: No
        type: String
        default: 
    client_certificate_verify_mode:
        description: Available only when the Client Certificate Verify is selected. Required by default.
        required: No
        type: String
        default: required
    client_sni_required:
        description: Require clients to use the TLS server name indication (SNI) extension to include the server hostname in the TLS client hello message. Then, the FortiADC system can select the appropriate local server certificate to present to the client.
        required: No
        type: String
        default: disable
    customized_ssl_ciphers_flag:
        description: Enable or disable the use of user-specified cipher suites. If enabled, you must specify an ordered list of a customized SSL cipher suites
        required: No
        type: String
        default: disable
    forward_proxy:
        description: By default, (SSL) Forward Proxy is disabled. When enabled, you'll have to configure additional settings noted below.
        required: No
        type: String
        default: disable
    forward_proxy_certificate_caching:
        description: Select a Forward Proxy Certificate Caching rule.
        required: No
        type: String
        default: 
    forward_proxy_intermediate_ca_group:
        description: Select a Forward Proxy Intermediate CA Group.
        required: No
        type: String
        default: 
    forward_proxy_local_signing_ca:
        description: Select a Forward Proxy Local Signing CA.
        required: No
        type: String
        default: SSLPROXY_LOCAL_CA
    http_forward_client_certificate:
        description: Disabled by default. When enabled, you must specify the client certificate forward header.
        required: No
        type: String
        default: disable
    http_forward_client_certificate_header:
        description: When Client Certificate Forward is enabled, specify the client certificate forward header.
        required: No
        type: String
        default: X-Client-Cert
    local_certificate_group:
        description: Select a local certificate group that includes the certificates this virtual server presents to SSL/TLS clients. This should be the backend servers' certificate.
        required: No
        type: String
        default: LOCAL_CERT_GROUP
    reject_ocsp_stapling_with_missing_nextupdate:
        description: This flag is meaningful only when you have configured OCSP stapling in Local Certificate Group.
        required: No
        type: String
        default: disable
    ssl_allowed_versions:
        description: Allowed SSL versions.
        required: No
        type: String
        default: tlsv1.1 tlsv1.2
    ssl_ciphers:
        description: SSL cipher suite.
        required: No
        type: List
        default: 
    ssl_ciphers_tlsv13:
        description: TLS v1.3 Cipher suite.
        required: No
        type: List
        default: 
    ssl_dh_param_size:
        description: Specify the pubkey length in Diffie Hellman.
        required: No
        type: String
        default: 1024bit
    ssl_dynamic_record_sizing:
        description: Allows ADC to dynamically adjust the size of TLS records based on the state of the connection, in order to prevent bottlenecks caused by the buffering of TLS record fragments.
        required: No
        type: String
        default: disable
    ssl_renegotiate_period:
        description: Specify the period in second (default), minute, or hour at which FortiADC will initiate SSL renegotiation.
        required: No
        type: String
        default: 0
    ssl_renegotiate_size:
        description: Specify the amount (MB) of application data that must have been transmitted over the SSL connection whenFortiADC initiates SSL renegotiation.
        required: No
        type: String
        default: 0
    ssl_renegotiation:
        description: Enable or disable SSL renegotiation from the client side.
        required: No
        type: String
        default: disable
    ssl_renegotiation_interval:
        description: Specify the minimum interval between two successive client-initiated SSL renegotiation requests. The unit of measurement can be second, minute, or hour, e.g., 100s, 20m, or 1h.
        required: No
        type: String
        default: -1
    ssl_secure_renegotiation:
        description: Secure renegotiation of SSL connections.
        required: No
        type: String
        default: require
    ssl_session_cache_flag:
        description: Allows to the same SSL client attempts to reconnect to this SSL server and requests a resumption of a previous SSL session.
        required: No
        type: String
        default: enable
    use_tls_tickets:
        description: Allows resuming TLS sessions by storing key material encrypted on the clients.
        required: No
        type: String
        default: enable
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
    - name: Manage Client SSL Profile
      fadcos_client_ssl_profile:
        action: add
        vdom: root
        name: test_csslp
"""

RETURN = """
fadcos_client_ssl_profile:
  description: The FortiADC client SSL profile object created or updated.
  returned: always
  type: string
"""

def add_client_ssl_profile(module, connection):

    payload = {
        'mkey': module.params['name'],
        'backend_ciphers_tlsv13': list_to_str(module.params['backend_ciphers_tlsv13']),
        'backend_customized_ssl_ciphers_flag': module.params['backend_customized_ssl_ciphers_flag'],
        'backend_ssl_OCSP_stapling_support': module.params['backend_ssl_OCSP_stapling_support'],
        'backend_ssl_allowed_versions': module.params['backend_ssl_allowed_versions'],
        'backend_ssl_ciphers': list_to_str(module.params['backend_ssl_ciphers']),
        'backend_ssl_sni_forward': module.params['backend_ssl_sni_forward'],
        'client_certificate_verify': module.params['client_certificate_verify'],
        'client_certificate_verify_mode': module.params['client_certificate_verify_mode'],
        'client_sni_required': module.params['client_sni_required'],
        'customized_ssl_ciphers_flag': module.params['customized_ssl_ciphers_flag'],
        'forward_proxy': module.params['forward_proxy'],
        'forward_proxy_certificate_caching': module.params['forward_proxy_certificate_caching'],
        'forward_proxy_intermediate_ca_group': module.params['forward_proxy_intermediate_ca_group'],
        'forward_proxy_local_signing_ca': module.params['forward_proxy_local_signing_ca'],
        'http-forward_client_certificate': module.params['http_forward_client_certificate'],
        'http-forward_client_certificate_header': module.params['http_forward_client_certificate_header'],
        'local_certificate_group': module.params['local_certificate_group'],
        'reject-ocsp-stapling-with-missing-nextupdate': module.params['reject_ocsp_stapling_with_missing_nextupdate'],
        'ssl-allowed_versions': module.params['ssl_allowed_versions'],
        'ssl_ciphers': list_to_str(module.params['ssl_ciphers']),
        'ssl_ciphers_tlsv13': list_to_str(module.params['ssl_ciphers_tlsv13']),
        'ssl_dh_param_size': module.params['ssl_dh_param_size'],
        'ssl_dynamic_record_sizing': module.params['ssl_dynamic_record_sizing'],
        'ssl_renegotiate_period': module.params['ssl_renegotiate_period'],
        'ssl_renegotiate_size': module.params['ssl_renegotiate_size'],
        'ssl_renegotiation': module.params['ssl_renegotiation'],
        'ssl_renegotiation_interval': module.params['ssl_renegotiation_interval'],
        'ssl_secure_renegotiation': module.params['ssl_secure_renegotiation'],
        'ssl_session_cache_flag': module.params['ssl_session_cache_flag'],
        'use_tls_tickets': module.params['use_tls_tickets'],
        }

    url = '/api/load_balance_client_ssl_profile'
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom
    
    code, response = connection.send_request(url, payload)

    return code, response

def get_client_ssl_profile(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/load_balance_client_ssl_profile'

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

def delete_client_ssl_profile(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/load_balance_client_ssl_profile?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')
    return code, response

def edit_client_ssl_profile(module, payload, connection):
    name = module.params['name']
    url = '/api/load_balance_client_ssl_profile?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'PUT')
    return code, response

def update_client_ssl_profile(module, data):
    res = False

    parameter_map = {
        'http_forward_client_certificate': 'http-forward_client_certificate',
        'http_forward_client_certificate_header': 'http-forward_client_certificate_header',
        'reject_ocsp_stapling_with_missing_nextupdate': 'reject-ocsp-stapling-with-missing-nextupdate',
        'ssl_allowed_versions': 'ssl-allowed_versions',
    }

    for param in module.params:
        key = parameter_map.get(param)
        if key == None:
            key = param
        if key in data:
            if key == 'ssl_ciphers' or key == 'ssl_ciphers_tlsv13' or key == 'backend_ssl_ciphers' or key == 'backend_ciphers_tlsv13':
                if list_need_update(module.params[param], data[key]):
                    data[key] = list_to_str(module.params[param])
                    res = True
            elif module.params[param] != data[ key]:
                data[key] = module.params[param]
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
        backend_ciphers_tlsv13=dict(type='list'),
        backend_customized_ssl_ciphers_flag=dict(type='str', default='enable'),
        backend_ssl_OCSP_stapling_support=dict(type='str', default='disable'),
        backend_ssl_allowed_versions=dict(type='str', default='sslv3 tlsv1.0 tlsv1.1 tlsv1.2'),
        backend_ssl_ciphers=dict(type='list'),
        backend_ssl_sni_forward=dict(type='str', default='disable'),
        client_certificate_verify=dict(type='str', default=''),
        client_certificate_verify_mode=dict(type='str', default='required'),
        client_sni_required=dict(type='str', default='disable'),
        customized_ssl_ciphers_flag=dict(type='str', default='disable'),
        forward_proxy=dict(type='str', default='disable'),
        forward_proxy_certificate_caching=dict(type='str', default=''),
        forward_proxy_intermediate_ca_group=dict(type='str', default=''),
        forward_proxy_local_signing_ca=dict(type='str', default='SSLPROXY_LOCAL_CA'),
        http_forward_client_certificate=dict(type='str', default='disable'),
        http_forward_client_certificate_header=dict(type='str', default='X-Client-Cert'),
        local_certificate_group=dict(type='str', default='LOCAL_CERT_GROUP'),
        reject_ocsp_stapling_with_missing_nextupdate=dict(type='str', default='disable'),
        ssl_allowed_versions=dict(type='str', default='tlsv1.1 tlsv1.2'),
        ssl_ciphers=dict(type='list'),
        ssl_ciphers_tlsv13=dict(type='list'),
        ssl_dh_param_size=dict(type='str', default='1024bit'),
        ssl_dynamic_record_sizing=dict(type='str', default='disable'),
        ssl_renegotiate_period=dict(type='str', default='0'),
        ssl_renegotiate_size=dict(type='str', default='0'),
        ssl_renegotiation=dict(type='str', default='disable'),
        ssl_renegotiation_interval=dict(type='str', default='-1'),
        ssl_secure_renegotiation=dict(type='str', default='require'),
        ssl_session_cache_flag=dict(type='str', default='enable'),
        use_tls_tickets=dict(type='str', default='enable'),
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
        code, response = add_client_ssl_profile(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_client_ssl_profile(module, connection)
        result['res'] = response
        result['ok'] = True
    elif action == 'edit':
        code, data = get_client_ssl_profile(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = update_client_ssl_profile(module, data['payload'])
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            code, response = edit_client_ssl_profile(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_client_ssl_profile(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = delete_client_ssl_profile(module, connection)
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
