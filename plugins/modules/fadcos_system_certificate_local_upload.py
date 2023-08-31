#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2023/04/06

from __future__ import (absolute_import, division, print_function)
import json
import urllib3
import sys
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_global_admin
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import prepare_multipart
import base64 
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import prepare_multipart_base64

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: fadcos_system_cerificate_local_upload
"""

EXAMPLES = """
"""

RETURN = """
"""

upload_url = '/api/upload/certificate_local'
upload_url_automated = '/api/system_certificate_local/automated'

edit_dict = {
}

def update_payload(module):
    payload = {
    'type': module.params['type'],
    'mkey': module.params['name'],
    'certificate-file': module.params['certificate_file'],
    'key-file': module.params['key_file'],
    'passwd': module.params['passwd'],
    'upload': module.params['upload'],
    'cert': module.params['cert'],
    'key': module.params['key'],
    'acme_service': module.params['acme_service'],
    'ca_group': module.params['ca_group'],
    'challenge_type': module.params['challenge_type'],
    'challenge_wait': module.params['challenge_wait'],
    'renew_win': module.params['renew_win'],
    'domain': module.params['domain'],
    'email': module.params['email'],
    'key_size': module.params['key_size'],
    'key_type': module.params['key_type'],
    'curve_name': module.params['curve_name'],
    'vdom': module.params['vdom'],
    }

    return payload

def update_url(module, url):
    vdom = module.params['vdom']
    if vdom and vdom != 'global' and vdom != 'Global':
        return url + '?vdom=' + module.params['vdom']
    else:
        return url + '?vdom=false'

def add_obj_certificate(module, connection):
    url = update_url(module, upload_url)
    payload = update_payload(module)
    
    if sys.version_info >= (3,6):
        data = {
                'type': payload['type'],
                'mkey': payload['mkey'],
                'passwd': payload['passwd'],
                'vdom': payload['vdom'],
                'certificate-file': payload['certificate-file'],
                'key-file': payload['key-file'],
                'cert': {
                    'filename': payload['certificate-file'],
                    },
                'key': {
                    'filename': payload['key-file'],
                    },
                'Content-Transfer-Encoding' : "base64",
                }
        content_type, b_data = prepare_multipart_base64(data)
    else:
        data = {
                'type': payload['type'],
                'mkey': payload['mkey'],
                'passwd': payload['passwd'],
                'vdom': payload['vdom'],
                'certificate-file': "",
                'cert': (payload['certificate-file'], open(payload['certificate-file']).read()),
                'key-file': "",
                'key': (payload['key-file'], open(payload['key-file']).read()),
                }
        b_data, content_type = urllib3.encode_multipart_formdata(data)

    headers = {
        'Content-type': content_type,
    }

    code, response = connection.send_url_request(url, b_data.decode('ascii'), headers=headers)
    return code, response

def add_obj_certificate_from_text(module, connection):
    url = update_url(module, upload_url)
    payload = update_payload(module)

    data = {
        'type': payload['type'],
        'mkey': payload['mkey'],
        'passwd': payload['passwd'],
        'cert': payload['cert'],
        'key': payload['key'],
        'upload' : payload['upload'],
        'vdom': payload['vdom'],
    }

    b_data, content_type = urllib3.encode_multipart_formdata(data)
    headers = {
        'Content-type': content_type,
    }

    code, response = connection.send_url_request(url, b_data.decode('ascii'), headers=headers)
    return code, response

def add_obj_pkcs12_certificate(module, connection):
    url = update_url(module, upload_url)
    payload = update_payload(module)

    if sys.version_info >= (3,6):
        data = {
                'type': payload['type'],
                'mkey': payload['mkey'],
                'passwd': payload['passwd'],
                'vdom': payload['vdom'],
                'certificate-file': payload['certificate-file'],
                'cert': {
                    'filename': payload['certificate-file'],
                    },
                'Content-Transfer-Encoding' : "base64",
                }
        content_type, b_data = prepare_multipart_base64(data)
    else:
        data = {
                'type': payload['type'],
                'mkey': payload['mkey'],
                'passwd': payload['passwd'],
                'vdom': payload['vdom'],
                'certificate-file': "",
                'cert': (payload['certificate-file'], open(payload['certificate-file']).read())
                }
        b_data, content_type = urllib3.encode_multipart_formdata(data)
    
    headers = {
        'Content-type': content_type,
    }

    code, response = connection.send_url_request(url, b_data.decode('ascii'), headers=headers)
    return code, response

def add_obj_local_certificate(module, connection):
    url = update_url(module, upload_url)
    payload = update_payload(module)

    if sys.version_info >= (3,6):
        data = {
                'type': payload['type'],
                'vdom': payload['vdom'],
                'certificate-file': payload['certificate-file'],
                'cert': {
                    'filename': payload['certificiate-file'],
                    },
                'Content-Transfer-Encodeing': "base64",
                }
        content_type, b_data = prepare_multipart_base64(data)
    else:
        data = {
                'type': payload['type'],
                'vdom': payload['vdom'],
                'certificate-file': "",
                'cert': (payload['certificate-file'], open(payload['certificate-file']).read())
                }
        b_data, content_type = urllib3.encode_multipart_formdata(data)
    
    headers = {
        'Content-type': content_type,
    }

    code, response = connection.send_url_request(url, b_data.decode('ascii'), headers=headers)
    return code, response

def add_obj_automated_certificate(module, connection):
    url = update_url(module, upload_url_automated)
    payload = update_payload(module)
    data = {
        'acme_service': payload['acme_service'],
        'ca_group': payload['ca_group'],
        'challenge_type': payload['challenge_type'],
        'challenge_wait': payload['challenge_wait'],
        'renew_win': payload['renew_win'],
        'domain': payload['domain'],
        'email': payload['email'],
        'key_size': payload['key_size'],
        'key_type': payload['key_type'],
        'curve_name': payload['curve_name'],
        'type': payload['type'],
        'mkey': payload['mkey'],
        'passwd': payload['passwd'],
        'vdom': payload['vdom'],
    }

    for key, value in list(data.items()):
        if not value:
            data.pop(key)

    return request_obj(url, data, connection, 'POST')

def add_obj(module, connection):
    if module.params['type'] == 'CertKey':
        if module.params['upload'] == 'text':
            return add_obj_certificate_from_text(module, connection)
        else:
            return add_obj_certificate(module, connection)    
    elif module.params['type'] == 'PKCS12':
        return add_obj_pkcs12_certificate(module, connection)
    elif module.params['type'] == 'LocalCert':
        return add_obj_local_certificate(module, connection)
    elif module.params['type'] == 'Automated':
        return add_obj_automated_certificate(module, connection)

def request_obj(url, payload, connection, action):
    code, response = connection.send_request(url, payload, action)

    return code, response

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []
    if action != 'add':
        res = False
        err_msg.append('The ' + action + 'is not supported.')

    return res, err_msg

def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        type=dict(type='str'),
        name=dict(type='str'),
        certificate_file=dict(type='str'),
        key_file=dict(type='str'),
        passwd=dict(type='str', default=''),
        upload=dict(type='str', default='upload'),
        cert=dict(type='str'),
        key=dict(type='str'),
        acme_service=dict(type='str'),
        ca_group=dict(type='str'),
        challenge_type=dict(type='str'),
        challenge_wait=dict(type='str'),
        renew_win=dict(type='str'),
        domain=dict(type='str'),
        email=dict(type='str'),
        key_size=dict(type='str', default='2048'),
        key_type=dict(type='str', default='RSA'),
        curve_name=dict(type='str'),
        vdom=dict(type='str', default='Global'),
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_msg = param_check(module, connection)
    if not param_pass:
        result['failed'] = True
        result['err_msg'] = param_msg
    elif action == 'add':
        code, response = add_obj(module, connection)
        result['changed'] = True
        result['res'] = response

    if 'res' in result.keys() and type(result['res']) is dict\
            and type(result['res']['payload']) is int and result['res']['payload'] < 0:
        result['err_msg'] = get_err_msg(connection, result['res']['payload'])
        result['changed'] = False
        result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
