#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import fadcos_argument_spec
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import get_err_msg
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_to_str
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import list_need_update
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_global_admin
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_vdom_enable
from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fadcos.fadcos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fadcos_admin
short_description: Configure FortiADC admin by RESTful API
description:
  - Manage admin on FortiADC devices including creating, updating, removing admin objects,
    All operations are performed RESTful API.
version_added: "2.8"
author: "Ansible by Red Hat (@rcarrillocruz)"
options:
  name:
    description:
      - Name of the admin.
    type: str
  trused_hosts:
    description:
      - trused hosts.
    required: True
    type: str
    default: 0.0.0.0/0 ::/0
  global_admin:
    description:
      - global admin.
    type: str
    default: yes
  profile:
    description:
      - profile
    type: str
  vdom:
    description:
      - Destionation object of the access rule.
    type: str
    default: root
  password:
    description:
      - password
    required: True
    type: str
"""

EXAMPLES = """
- name: Create admin
  fadcos_admin:
    name: newuser
    password: newpwd

"""

RETURN = """
fadcos_admin:
  description: The FortiADC admin object created or updated.
  returned: always.
  type: string
"""

before = {}
after = {}
rep_dict = {
    'trused_hosts': 'trusted-host',
    'global_admin': 'is-system-admin',
    'ldap_server': 'auth_ldap_server_id',
    'radius_server': 'auth_radius_server_id',    
    'admin_type': 'admin-type',
    'oldpassword': 'oldpwd'
}


def add_admin(module, connection):
    after['added'] = module.params
    name = module.params['name']
    trused_hosts = module.params['trused_hosts']
    global_admin = module.params['global_admin']
    profile = module.params['profile']
    vdom = module.params['vdom']
    wildcard = module.params['wildcard']
    auth_stratgey = module.params['auth_stratgey']
    ldap_server = module.params['ldap_server']
    radius_server = module.params['radius_server']
    password = module.params['password']
    admin_type = module.params['admin_type']
    auth_strategy = module.params['auth_strategy']

    payload = {'mkey': name,
               'is-system-admin': global_admin,
               'trusted-host': trused_hosts,
               'profile': profile,
               'vdom': vdom,
               'wildcard': wildcard,
               'auth_stratgey': auth_stratgey,
               'passwd': password,
               'auth_ldap_server_id': ldap_server,
               'auth_radius_server_id': radius_server,
               'admin-type': admin_type,
               'auth_strategy': auth_strategy,
               }

    url = '/api/system_admin'
    if not is_global_admin(connection):
        url += '?vdom=' + module.params['vdom'].split(" ")[0]

    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload)

    return code, response


def edit_admin(module, payload, connection):
    name = module.params['name']
    url = '/api/system_admin?mkey=' + name

    if not is_global_admin(connection):
        url += '&vdom=' + module.params['vdom'].split(" ")[0]

    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_admin(module, connection):
    name = module.params['name']
    payload = {}
    url = '/api/system_admin'

    if name:
        url += '?mkey=' + name
    if not is_global_admin(connection):
        if name:
            url += '&'
        else:
            url += '?'
        url += 'vdom=' + module.params['vdom'].split(" ")[0]

    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_admin(module, connection):
    after['deleted'] = module.params
    name = module.params['name']
    payload = {}
    url = '/api/system_admin?mkey=' + name

    if not is_global_admin(connection):
        url += '&vdom=' + module.params['vdom'].split(" ")[0]

    if module.check_mode:
        code = 0
        response = 'Check mode: changes detected.' 
    else:
        code, response = connection.send_request(url, payload, 'DELETE')

    return code, response

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
    if module.params['oldpassword'] and module.params['password'] and module.params['oldpassword'] != module.params['password']:
        data['oldpwd'] = module.params['oldpassword']
        res = True
    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'add' or action == 'edit' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    if module.params['auth_stratgey'] == 'local' and module.params['password'] is None:
        err_msg = 'password need to set'
        res = False
    if module.params['auth_stratgey'] == 'radius' and module.params['radius_server'] is None:
        err_msg = 'radius_server need to set'
        res = False
    if module.params['auth_stratgey'] == 'ldap' and module.params['ldap_server'] is None:
        err_msg = 'ldap_server need to set'
        res = False
    if module.params['global_admin'] and module.params['global_admin'] == "False":
        module.params['global_admin'] = "no"
    elif module.params['global_admin'] and module.params['global_admin'] == "True":
        module.params['global_admin'] = "yes"

    if not module.params['vdom'] and not is_global_admin(connection):
        err_msg = 'user is not global admin then vdom need to set'
        res = False

    if module.params['vdom'] and not is_global_admin(connection):
        if len(module.params['vdom']) > 1:
            err_msg = 'user is not global admin can not access multi vdom for new admin'
            res = False
        elif not is_user_in_vdom(connection, module.params['vdom'].split(" ")[0]):
            err_msg = 'user is not global admin can not access the vdom ' + \
                module.params['vdom'].split(" ")[0] + ' for new admin'
            res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        trused_hosts=dict(type='str', default='0.0.0.0/0 ::/0'),
        global_admin=dict(type='str', default='no'),
        profile=dict(type='str', default='super_admin_prof'),
        vdom=dict(type='str'),
        auth_stratgey=dict(type='str'),
        oldpassword=dict(type='str'),
        password=dict(type='str'),
        radius_server=dict(type='str'),
        ldap_server=dict(type='str'),
        wildcard=dict(type='str', default='disable'),
        admin_type=dict(type='str', default='normal'),
        auth_strategy=dict(type='str', default='local'),
    )
    argument_spec.update(fadcos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_err = param_check(module, connection)
    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
        module.exit_json(**result)
    code, data = get_admin(module, connection)
    if action == 'add':
        if isinstance(data, dict) and 'payload' in data and data['payload'] and isinstance(data['payload'], dict):
            result['res'] = "Duplicated Entry."
        else:
            code, response = add_admin(module, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'get':
        code, response = get_admin(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_admin(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            res, new_data = needs_update(module, data['payload'])
        else:
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            code, response = edit_admin(module, new_data, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_admin(module, connection)
        if isinstance(data, dict) and 'payload' in data and data['payload'] and type(data['payload']) is not int:
            code, response = delete_admin(module, connection)
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
    else:
        if module.check_mode:
           result['res'] = 'Check mode: no changes detected.'  

    module.exit_json(**result)


if __name__ == '__main__':
    main()
