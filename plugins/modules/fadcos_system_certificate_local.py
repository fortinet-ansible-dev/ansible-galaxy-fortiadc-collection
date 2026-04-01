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
before = {}
after = {}
rep_dict = {
    'name': 'mkey',
}

def module_err_exit(module, mesg):
    result = {}
    result['err_msg'] = mesg
    result['failed'] = True
    result['changed'] = False
    module.exit_json(**result)

check_mode_enabled = False

def send_request(url, payload, connection, action):
    if check_mode_enabled:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, action)
    return code, response

def add_obj(module, connection):
    after['added'] = module.params
    payload = {}
    params = module.params
    vdom = module.params['vdom']
    for key in params.keys():
        if params[key] is not None:
            data_key = None
            if key in rep_dict.keys():
                data_key = rep_dict[key]
            else:
                data_key = key #This key's value is not changed. 
            payload[data_key] = params[key] 
    url = obj_url
    if is_vdom_enable(connection) and module.params['vdom']:
        url += '?vdom=' + vdom
    code, response = send_request(url, payload, connection, 'POST')
    return code, response


def edit_obj(module, payload, connection):
    name = module.params['name']
    vdom = module.params['vdom']
    url = obj_url
    if name:
        url += '?mkey=' + name
    else:
        module_err_exit(module, 'edit action needs the parameter \'name\' not to be empty.')
    if is_vdom_enable(connection) and module.params['vdom']:
        vdom = module.params['vdom']
        if name:
            url += '&vdom=' + vdom
        else:
            url += '?vdom=' + vdom

    code, response = send_request(url, payload, connection, 'PUT')

    return code, response


def get_obj(module, connection):
    name = module.params['name']
    vdom = module.params['vdom']
    payload = {}
    if name:
        url = obj_url + '?mkey=' + name
    else:
        url = obj_url
    if is_vdom_enable(connection) and module.params['vdom']:
        vdom = module.params['vdom']
        if name:
            url += '&vdom=' + vdom
        else:
            url += '?vdom=' + vdom
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    after['deleted'] = module.params
    name = module.params['name']
    vdom = module.params['vdom']
    payload = {}
    url = obj_url
    if name:
        url = obj_url + '?mkey=' + name
    else:
        module_err_exit(module, 'delete action needs the parameter \'name\' not to be empty.')
    if is_vdom_enable(connection) and module.params['vdom']:
        vdom = module.params['vdom']
        url += '&vdom=' + vdom
    
    code, response = send_request(url, payload, connection, 'DELETE')
    return code, response


def combine_dict(src_dict, dst_dict):
    changed = False
    for key in dst_dict:
        if key in src_dict and src_dict[key] is not None and dst_dict[key] != src_dict[key]:
            dst_dict[key] = src_dict[key]
            changed = True

    return changed

def needs_update(module, data):
    res = False
    params = module.params
    for key in params.keys():
        if params[key] is not None:
            data_key = None
            if key in data.keys() and params[key] != data[key]:
                data_key = key 
            elif key in rep_dict.keys() and rep_dict[key] in data.keys() and params[key] != data[rep_dict[key]] :
                data_key = rep_dict[key]
            else:
                continue #This key's value is not changed. 
            if isinstance(params[key], str) and isinstance(data[data_key], str) and params[key].rstrip() == data[data_key].rstrip():
                continue #some sring values returned from API have trailing whitespace
            before[key] = data[data_key]
            after[key] = params[key]
            data[data_key] = params[key]
            res = True

    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = []

    if action != 'add' and action != 'get' and action != 'edit' and action != 'remove':
        res = False
        err_msg.append('The '+ action + 'is not supported.')
        
    if is_vdom_enable(connection) and module.params['vdom'] and not is_user_in_vdom(connection, module.params['vdom']):
        err_msg.append('The user can not access the vdom ' + module.params['vdom'])
        res = False

    return res, err_msg

def main():
    global check_mode_enabled
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
                           required_if=required_if,
                           supports_check_mode=True)
    connection = Connection(module._socket_path)

    if module.check_mode:
        check_mode_enabled = True
    action = module.params['action']
    result = {}
    param_pass, param_err = param_check(module, connection)
    module.params.pop('action')

    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
        module.exit_json(**result)

    code, data = get_obj(module, connection)
    if action == 'add':
        if 'payload' in data.keys() and data['payload'] and isinstance(data['payload'], dict):
            result['res'] = "Duplicated entry detected."
        else:
            code, response = add_obj(module, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'get':
        result['res'] = data
    elif action == 'edit':
        if 'payload' in data.keys() and data['payload'] and isinstance(data['payload'], dict):
            res, new_data = needs_update(module, data['payload'])
        else:
            res = False
            result['err_msg'] = 'Entry not found.'
        if res:
            code, response = edit_obj(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete' or action == 'remove':
        if 'payload' in data.keys() and data['payload'] and isinstance(data['payload'], dict):
            code, response = delete_obj(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['changed'] = False
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
