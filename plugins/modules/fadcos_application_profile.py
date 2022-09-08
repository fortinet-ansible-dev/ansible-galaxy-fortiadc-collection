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
module: fadcos_application_profile
description:
	Configure SSL offloading on FortiADC devices via RESTful APIs
    Supported Types: TCP, UDP, L7 TCP, L7 UDP, HTTP, HTTPS, FTP, TCPS
                    HTTP Turbo, EXPLICIT HTTP, RDP, IP, RTMP, RTSP
version_added: "v1.0.0"
author: asri@fortinet.com
options:
    action:
        description: Type of action to perform on the object
        required: Yes
        type: String
        default: N/A
    name:
        description: Application profile name.
        required: Yes
        type: String
        default: N/A
    type:
        description: Application profile type.
        required: Yes
        type: String
        default: N/A
    timeout_tcp_session:
        description: Client-side timeout for connections where the client has not sent a FIN signal, but the connection has been idle. The default is 100 seconds. The valid range is 1 to 86,400.
        required: No
        type: String
        default: 100
    timeout_tcp_session_after_fin:
        description: Client-side connection timeout. The default is 100 seconds. The valid range is 1 to 86,400.
        required: No
        type: String
        default: 100
    ip_reputation:
        description: Enable to apply FortiGuard IP reputation service. 
        required: No
        type: String
        default: disable
    ip_reputation_redirect:
        description: Type a URL including the FQDN/IP and path, if any, to which a client will be redirected if the request violates the IP reputation policy.
        required: No
        type: String
        default: http://
    stateless:
        description: Enable to apply UDP stateless function.
        required: No
        type: String
        default: disable
    timeout_udp_session:
        description: Client-side session timeout. The default is 100 seconds. The valid range is 1 to 86,400.
        required: No
        type: String
        default: 100
    client_timeout:
        description: This timeout is counted as the amount of time when the client did not send a complete request HTTP header to the FortiADC after the client connected to the FortiADC. If this timeout expires, FortiADC will send a 408 message to client and close the connection to the client.
        required: No
        type: String
        default: 50
    server_timeout:
        description: This timeout is counted as the amount of time when the server did not send a complete response HTTP header to the FortiADC after the FortiADC sent a request to server. If this timeout expires, FortiADC will close the server side connection and send a 503 message to the client and close the connection to the client.
        required: No
        type: String
        default: 50
    connect_timeout:
        description: This timeout is counted as the amount of time during which FortiADC tried to connect to the server with TCP SYN. After this timeout, if TCP connection is not established, FortiADC will drop this current connection to server and respond with a 503 message to client side and close the connection to the client.
        required: No
        type: String
        default: 5
    queue_timeout:
        description: This timeout is counted as the amount of time during which the request is queued in the dispatched queue. When the request cannot be dispatched to a server by a load balance method (for example, the server's connection limited is reached), it will be put into a queue. If this timeout expires, the request in the queue will be dropped and FortiADC will respond with a 503 message to client side and close the connection to the client.
        required: No
        type: String
        default: 5
    http_send_timeout:
        description: This timeout is counted as the amount of time it took FortiADC to send a response body data (not including the header); the time is counted starting from when the body is transferred. If this timeout expires, FortiADC will close the connection of both side.
        required: No
        type: String
        default: 0
    http_request_timeout:
        description: This timeout is counted as the amount of time the client did not send a complete request (including both HTTP header and request body) to FortiADC after the client connected to FortiADC. If this timeout expires, FortiADC will send a 408 message to client and close the connection to the client.
        required: No
        type: String
        default: 50
    http_keepalive_timeout:
        description: This timeout is counted as the time FortiADC can wait for a new request after the previous transaction is completed. This is an idle timeout if the client does not send anything in this period. If this timeout expires, FortiADC will close the connection to the client.
        required: No
        type: String
        default: 50
    client_address:
        description: Use the original client IP address as the source address when connecting to the real server.
        required: No
        type: String
        default: disable
    http_x_forwarded_for:
        description: Enable this option to append the client IP address found in IP layer packets to the HTTP header.
        required: No
        type: String
        default: disable
    http_x_forwarded_for_header:
        description: Specify a custom name for the HTTP header which carries the client IP address. 
        required: No
        type: String
        default: 
    http_mode:
        description: HTTP mode. (serverclose/onceonly/KeepAlive) 
        required: No
        type: String
        default: KeepAlive
    security_mode:
        description: Security Mode (none/explicit/implicit)
        required: No
        type: String
        default: none
    timeout_ip_session:
        description: Client-side session timeout. The default is 100 seconds. The valid range is 1 to 86,400.
        required: No
        type: String
        default: 100
    timeout_radius_session:
        description: The default is 300 seconds. The valid range is 1 to 3,600.
        required: No
        type: String
        default: 300
    source_port:
        description: Use the original client port as the source port when connecting to the real server.
        required: No
        type: String
        default: disable
    dynamic_auth:
        description: Enable or disable Dynamic Authorization for RADIUS Change of Authorization(CoA)
        required: No
        type: String
        default: disable
    dynamic_auth_port:
        description: Configures the UDP port for CoA requests. The default is 3799.
        required: No
        type: String
        default: 3799
    max_header_size:
        description: Specify the maximum size of the RTSP header.
        required: No
        type: String
        default: 4096
    max_http_headers:
        description: Adjust the max header number that HTTP/HTTPS VS can process for every request or response. If a request or response has a header over this limit, it will be dropped, and error message 400 will be returned.
        required: No
        type: String
        default: 100
    tune_bufsize:
        description: Adjust the value of the HTTP/HTTPS VS's connection buffer size.
        required: No
        type: String
        default: 8030
    response_half_closed_request:
        description: Continue to response to the half-closed connections.
        required: No
        type: String
        default: disable
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
    - name: Manage Application Profile
      fadcos_application_profile:
        action: add
        name: test_app
        type: tcp
        timeout_tcp_session: 150
        ip_reputation: disable
"""

RETURN = """
fadcos_application_profile:
  description: The FortiADC application profile object created or updated.
  returned: always
  type: string
"""

def add_app_profile(module, connection):

    payload = {
        'mkey': module.params['name'],
        'type': module.params['type'],
        'timeout_tcp_session': module.params['timeout_tcp_session'],
        'timeout_tcp_session_after_fin': module.params['timeout_tcp_session_after_fin'],
        'ip_reputation': module.params['ip_reputation'],
        'ip_reputation_redirect': module.params['ip_reputation_redirect'],
        'stateless': module.params['stateless'],
        'timeout_udp_session': module.params['timeout_udp_session'],
        'client_timeout': module.params['client_timeout'],
        'server_timeout': module.params['server_timeout'],
        'connect_timeout': module.params['connect_timeout'],
        'queue_timeout': module.params['queue_timeout'],
        'http_send_timeout': module.params['http_send_timeout'],
        'http_request_timeout': module.params['http_request_timeout'],
        'http_keepalive_timeout': module.params['http_keepalive_timeout'],
        'client_address': module.params['client_address'],
        'http_x_forwarded_for': module.params['http_x_forwarded_for'],
        'http_x_forwarded_for_header': module.params['http_x_forwarded_for_header'],
        'http_mode': module.params['http_mode'],
        'security-mode': module.params['security_mode'],
        'timeout_ip_session': module.params['timeout_ip_session'],
        'timeout_radius_session': module.params['timeout_radius_session'],
        'source_port': module.params['source_port'],
        'dynamic_auth': module.params['dynamic_auth'],
        'dynamic_auth_port': module.params['dynamic_auth_port'],
        'max_header_size': module.params['max_header_size'],
        'max_http_headers': module.params['max_http_headers'],
        'tune-bufsize': module.params['tune_bufsize'],
        'response_half_closed_request': module.params['response_half_closed_request'],
        }

    url = '/api/load_balance_profile'
    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '?vdom=' + vdom
    
    code, response = connection.send_request(url, payload)

    return code, response

def get_app_profile(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/load_balance_profile'

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

def delete_app_profile(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/load_balance_profile?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'DELETE')
    return code, response

def edit_app_profile(module, payload, connection):
    name = module.params['name']
    url = '/api/load_balance_profile?mkey=' + name

    if is_vdom_enable(connection):
        vdom = module.params['vdom']
        url += '&vdom=' + vdom

    code, response = connection.send_request(url, payload, 'PUT')
    return code, response

def update_app_profile(module, data):
    res = False

    parameter_map = {
        'security_mode': 'security-mode',
        'tune_bufsize': 'tune-bufsize',
    }

    for param in module.params:
        key = parameter_map.get(param)
        if key == None:
            key = param
        if key in data and module.params[param] != data[key]:
            data[key] = module.params[param]
            res = True

    return res, data

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if (action == 'add' or action == 'edit' or action == 'delete') and not module.params['name']:
        err_msg.append('The application profile name is required.')
        res = False
    if action == 'add' and not module.params['type']:
        err_msg.append('The application profile type is required.')
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
        type=dict(type='str'),
        timeout_tcp_session=dict(type='str', default='100'),
        timeout_tcp_session_after_fin=dict(type='str', default='100'),
        ip_reputation=dict(type='str', default='disable'),
        ip_reputation_redirect=dict(type='str', default='http://'),
        stateless=dict(type='str', default='disable'),
        timeout_udp_session=dict(type='str', default='100'),
        client_timeout=dict(type='str', default='50'),
        server_timeout=dict(type='str', default='50'),
        connect_timeout=dict(type='str', default='5'),
        queue_timeout=dict(type='str', default='5'),
        http_send_timeout=dict(type='str', default='0'),
        http_request_timeout=dict(type='str', default='50'),
        http_keepalive_timeout=dict(type='str', default='50'),
        client_address=dict(type='str', default='disable'),
        http_x_forwarded_for=dict(type='str', default='disable'),
        http_x_forwarded_for_header=dict(type='str', default=''),
        http_mode=dict(type='str', default='KeepAlive'),
        security_mode=dict(type='str', default='none'),
        timeout_ip_session=dict(type='str', default='100'),
        timeout_radius_session=dict(type='str', default='300'),
        source_port=dict(type='str', default='disable'),
        dynamic_auth=dict(type='str', default='disable'),
        dynamic_auth_port=dict(type='str', default='3799'),
        max_header_size=dict(type='str', default='4096'),
        max_http_headers=dict(type='str', default='100'),
        tune_bufsize=dict(type='str', default='8030'),
        response_half_closed_request=dict(type='str', default='disable'),
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
        code, response = add_app_profile(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_app_profile(module, connection)
        result['res'] = response
        result['ok'] = True
    elif action == 'edit':
        code, data = get_app_profile(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            res, new_data = update_app_profile(module, data['payload'])
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            code, response = edit_app_profile(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_app_profile(module, connection)
        if 'payload' in data.keys() and data['payload'] and type(data['payload']) is not int:
            code, response = delete_app_profile(module, connection)
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
