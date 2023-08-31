#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2023/04/06

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_vdom_enable
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: fadcos_system_certificate_local
options:
    action:
        description: Type of action to perform on the object
        required: Yes
        type: String
        options: add, get, remove

    name:
        description: Certifate name.
        required: Yes
        type: String

    id_type:
        description: Specify the ID type.
        required: No
        type: List
        default: ip
        options: ip, domain, email

    ip:
        description: Specify the IP.
        type: String
        depend on: id_type-ip

    domain:
        description: Specify the domain.
        type: String
        depend on: id_type-domain

    email:
        description: Specify the email.
        type: String
        depend on: id_type-email

    orgUnit:
        description: Specify the organization.
        required: No
        type: List

    org:
        description: Specify the organization.
        required: No
        type: String

    city:
        description: Specify the city/locality.
        required: No
        type: String

    state:
        description: Specify the state/province.
        required: No
        type: String

    country:
        description: Specify the country/region.
        required: No
        type: String

    orgEmail:
        description: Organization Email.
        required: No
        type: String

    san:
        description: Specify the Suubject Akternative Name.
        required: No
        type: String

    enc_meth:
        description: Specify the Private Key Encryption.
        required: No
        type: String
        default: aes128
        options: aes128, aes192, aes256

    k_pwd:
        description: Specify the Private Key Password.
        required: No
        type: String

    keyType:
        description: Specify the Key Type.
        required: No
        type: String
        default: 1
        options: 1(RSA), 2(ECDSA)

    keySize:
        description: Specify the Key Size.
        type: String
        default: 512
        options: 512, 1024, 1536, 2048, 4096
        depend on: keyType-1(RSA)

    hash:
        description: Specify the Hash Function
        type: String
        default: SHA1
        options: SHA1, SHA256
        depend on: keyType-1(RSA)

    keySizeECDSA:
        description: Specify the key Size
        type: String
        default: 256
        options: 256(prime256v1), 384(secp384r1), 512(secp512r1)
        depend on: keyType-2(ECDSA)

    enrollMethod:
        description: Enrollment Method
        required: No
        type: String
        default: file
        options: file, scep
        note: keyType ECDSA only has file method

    scep_url:
        description: SCEP URL
        type: String
        depend on: enrollMethod-scep

    c_pwd:
        description: Challenge PassWord
        required: No
        type: String
        depend on: enrollMethod-scep

    ca_id:
        description: CA Identifer
        type: String
        default: CAIdentifer
        depend on: enrollMethod-scep
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/system_certificate_local'

edit_dict = {
}

def update_payload(module):
    payload = {
    'mkey': module.params['name'],
    'id_type': module.params['id_type'],
    'ip': module.params['ip'],
    'domain': module.params['domain'],
    'orgUnit': module.params['orgUnit'],
    'org': module.params['org'],
    'city': module.params['city'],
    'state': module.params['state'],
    'country': module.params['country'],
    'orgEmail': module.params['orgEmail'],
    'san': module.params['san'],
    'enc_meth': module.params['enc_meth'],
    'k_pwd': module.params['k_pwd'],
    'keyType': module.params['keyType'],
    'keySize': module.params['keySize'],
    'hash': module.params['hash'],
    'keySizeECDSA': module.params['keySizeECDSA'],
    'enrollMethod': module.params['enrollMethod'],
    'scep_url': module.params['scep_url'],
    'c_pwd': module.params['c_pwd'],
    'ca_id': module.params['ca_id'],
    }

    return payload

def update_url(module, connection, url):
    if is_vdom_enable(connection):
        return url + '?vdom=' + module.params['vdom']
    else:
        return url

def get_obj(module, connection):
    payload = {}
    url = update_url(module, connection, obj_url)

    return request_obj(url, payload, connection, 'GET')

def add_obj(module, connection):
    url = update_url(module, connection, obj_url)
    payload = update_payload(module)

    return request_obj(url, payload, connection, 'POST')

def edit_obj(module, connection):
    payload = update_payload(module)
    if is_vdom_enable(connection):
        url = obj_url + '?vdom=' + module.params['vdom'] + '&mkey=' + payload['mkey']
    else:
        url = obj_url + '?mkey=' + payload['mkey']

    return request_obj(url, payload, connection, 'PUT')

def remove_obj(module, connection):
    payload = update_payload(module)
    if is_vdom_enable(connection):
        url = obj_url + '?vdom=' + module.params['vdom'] + '&mkey=' + payload['mkey']
    else:
        url = obj_url + '?mkey=' + payload['mkey']
    return request_obj(url, payload, connection, 'DELETE')

def request_obj(url, payload, connection, action):
    code, response = connection.send_request(url, payload, action)

    return code, response

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if action != 'add' and action != 'get' and action != 'edit' and action != 'remove':
        res = False
        err_msg.append('The '+ action + 'is not supported.')
    if is_vdom_enable(connection) and not module.params['vdom']:
        err_msg.append('The vdom is enable in system setting, vdom must be set.')
        res = False
    elif is_vdom_enable(connection) and module.params['vdom'] and not is_user_in_vdom(connection, module.params['vdom']):
        err_msg.append('The user can not access the vdom ' + module.params['vdom'])
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        id_type=dict(type='str', default='ip'),
        ip=dict(type='str', default='192.0.2.1'),
        domain=dict(type='str', default='www.example.com'),
        orgUnit=dict(type='list'),
        org=dict(type='str'),
        city=dict(type='str'),
        state=dict(type='str'),
        country=dict(type='str', default='AF'),
        orgEmail=dict(type='str'),
        san=dict(type='str'),
        enc_meth=dict(type='str', default='aes128'),
        k_pwd=dict(type='str'),
        keyType=dict(type='str', default='1'),
        keySize=dict(type='str', default='512'),
        hash=dict(type='str', default='SHA1'),
        keySizeECDSA=dict(type='str', default='256'),
        enrollMethod=dict(type='str', default='file'),
        scep_url=dict(type='str'),
        c_pwd=dict(type='str'),
        ca_id=dict(type='str'),
        vdom=dict(type='str'),
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
    elif action == 'get':
        code, response = get_obj(module, connection)
        result['res'] = response
    elif action == 'add':
        code, response = add_obj(module, connection)
        result['changed'] = True
        result['res'] = response
    elif action == 'remove':
        code, response = remove_obj(module, connection)
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
